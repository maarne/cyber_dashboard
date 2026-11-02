"""Fixed standard-utility adapters. All network work is bounded and cancellable."""
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

from app.services.asset_probe_policy import ProbePolicyError, hostname

EXECUTABLES = {name: next((p for p in (f'/usr/bin/{name}', f'/bin/{name}') if Path(p).is_file() and os.access(p, os.X_OK)), None)
               for name in ('curl', 'ping', 'nmap')}


class ProbeFailure(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def capabilities():
    return {'https': bool(EXECUTABLES['curl']), 'http': bool(EXECUTABLES['curl']),
            'icmp': bool(EXECUTABLES['ping']), 'tcp': bool(EXECUTABLES['nmap']),
            'discovery': bool(EXECUTABLES['nmap']),
            'note': 'Installed tools only; ICMP/kernel and routing support is verified by actual requested checks. No test traffic sent.'}


def bounded_process(mode, value, *, timeout=5, maximum=4096, cancelled=lambda: False):
    """Never inherit signing keys, proxy variables, curl config or user subprocess options."""
    command = [sys.executable, '-B', '-m', 'app.probe_process', mode, value]
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/nonexistent',
                   'CURL_HOME': '/nonexistent', 'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               env=environment, cwd=str(Path(__file__).resolve().parents[2]), start_new_session=True, close_fds=True)
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                if cancelled():
                    raise ProbeFailure('cancelled')
                if time.monotonic() >= deadline:
                    raise ProbeFailure('execution_timeout')
                events = selector.select(min(.2, max(0, deadline - time.monotonic())))
                if events:
                    chunk = os.read(process.stdout.fileno(), 8192)
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > maximum:
                        raise ProbeFailure('output_limit')
            try:
                code = process.wait(timeout=max(.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as exc:
                raise ProbeFailure('execution_timeout') from exc
            return code, bytes(output)
    finally:
        # Also terminate descendants if the utility exited before them.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdout.close()


def resolve(target, policy, cancelled=lambda: False):
    target = policy.target(target)
    try:
        return [policy.approve(str(ipaddress.ip_address(target)))]
    except ValueError:
        pass
    code, output = bounded_process('resolve', target, timeout=3, cancelled=cancelled)
    if code:
        raise ProbeFailure('dns_unavailable')
    try:
        values = json.loads(output)
        if not isinstance(values, list) or not 1 <= len(values) <= 8:
            raise ValueError()
        return sorted({policy.approve(value) for value in values})
    except ProbePolicyError:
        raise
    except (ValueError, TypeError) as exc:
        raise ProbeFailure('dns_unavailable') from exc


def reverse_name(ip, policy, confirm=False, cancelled=lambda: False):
    code, output = bounded_process('reverse', policy.approve(ip), timeout=2, cancelled=cancelled)
    if code:
        return []
    try:
        values = json.loads(output)
        if not isinstance(values, list) or len(values) > 8:
            return []
        result = []
        for name in values:
            name = hostname(name)
            verified = False
            if confirm:
                try:
                    verified = ip in resolve(name, policy, cancelled)
                except (ProbeFailure, ProbePolicyError):
                    pass
            result.append({'name': name, 'source': 'PTR', 'forward_confirmed': verified})
        return result
    except (ValueError, TypeError):
        return []


def run_utility(name, arguments, timeout, maximum=4096, cancelled=lambda: False):
    executable = EXECUTABLES[name]
    if not executable:
        raise ProbeFailure('utility_unavailable')
    return bounded_process('exec', json.dumps([executable, *arguments]), timeout=timeout, maximum=maximum, cancelled=cancelled)


def parse_nmap(output, expected):
    if len(output) > 512 * 1024:
        raise ProbeFailure('output_limit')
    # Nmap emits this harmless declaration. All other DTDs/entities are forbidden.
    output = output.replace(b'<!DOCTYPE nmaprun>', b'')
    if re.search(br'<!\s*(?:DOCTYPE|ENTITY)', output, re.I):
        raise ProbeFailure('invalid_scanner_output')
    try:
        depth, count = 0, 0
        for event, _ in ET.iterparse(io.BytesIO(output), events=('start', 'end')):
            if event == 'start':
                depth += 1; count += 1
                if depth > 12 or count > 10000:
                    raise ValueError()
            else:
                depth -= 1
        root = ET.fromstring(output)
        if root.tag != 'nmaprun' or root.find("runstats/finished").get('exit') != 'success':
            raise ValueError()
        records, seen = [], set()
        for host in root.findall('host'):
            addr = host.find('address')
            if addr is None:
                continue
            ip = str(ipaddress.ip_address(addr.get('addr')))
            if ip not in expected or ip in seen:
                raise ValueError()
            seen.add(ip)
            status = host.find('status')
            if status is not None and status.get('state') == 'up':
                records.append({'address': ip, 'evidence': 'discovery_response',
                                'open_ports': [int(port.get('portid')) for port in host.findall('ports/port')
                                               if port.find('state') is not None and port.find('state').get('state') == 'open']})
        return records
    except (ET.ParseError, ValueError, TypeError, AttributeError) as exc:
        raise ProbeFailure('invalid_scanner_output') from exc


def discover(addresses, settings, cancelled=lambda: False):
    if len(addresses) > 8:
        raise ProbeFailure('chunk_limit')
    ipv6 = ':' in addresses[0]
    if any((':' in ip) != ipv6 for ip in addresses):
        raise ProbeFailure('mixed_address_family')
    arguments = ['--unprivileged', '-sn', '-n', '-PS' + ','.join(map(str, settings['ports'])),
                 '--max-retries', '0', '--host-timeout', f"{settings['timeout_seconds'] * 1000}ms",
                 '--max-parallelism', '8', '--no-stylesheet', '-oX', '-']
    if ipv6:
        arguments.append('-6')
    code, output = run_utility('nmap', [*arguments, *addresses], timeout=8, maximum=512 * 1024, cancelled=cancelled)
    if code:
        raise ProbeFailure('discovery_unavailable')
    return parse_nmap(output, set(addresses))


def check(settings, ip, cancelled=lambda: False):
    start = time.monotonic()
    method, timeout = settings['method'], settings['timeout_seconds']
    code_label, outcome, metadata = 'check_failed', 'down', {}
    if method in ('https', 'http'):
        target = settings['target']; port = settings['port'] or (443 if method == 'https' else 80)
        url_host = f'[{target}]' if ':' in target else target
        binding_ip = f'[{ip}]' if ':' in ip else ip
        args = ['--disable', '--silent', '--show-error', '--noproxy', '*', '--proto', '=http,https',
                '--max-time', str(timeout), '--connect-timeout', str(timeout),
                '--output', '-', '--write-out', '\nCYBERDASH:%{http_code}', '--request', settings['http_method'],
                '--max-redirs', '0']
        try:
            ipaddress.ip_address(target)
        except ValueError:
            args.extend(['--resolve', f'{target}:{port}:{binding_ip}'])
        if settings['http_method'] == 'HEAD':
            args.append('--head')
        else:
            args.extend(['--max-filesize', '65536'])
        code, output = run_utility('curl', [*args, '--url', f'{method}://{url_host}:{port}{settings["path"]}'], timeout=timeout + 1, maximum=69632, cancelled=cancelled)
        match = re.search(br'CYBERDASH:(\d{3})\s*$', output)
        http_code = int(match[1]) if match else 0
        metadata['http_code'] = http_code or None
        if code == 0 and http_code in settings['expected_codes']:
            outcome, code_label = 'up', 'expected_http_response'
        elif code == 0:
            code_label = 'unexpected_http_status'
        elif code in (51, 60):
            code_label = 'tls_verification_failed'
        elif code == 28:
            code_label = 'target_timeout'
        elif code == 7:
            if any(value in output.lower() for value in (b'network is unreachable', b'no route to host', b'permission denied')):
                outcome, code_label = 'unknown', 'runner_network_unavailable'
            else:
                code_label = 'connection_failed'
        else:
            outcome, code_label = 'unknown', 'http_check_unavailable'
    elif method == 'icmp':
        code, output = run_utility('ping', ['-n', '-c', '1', '-W', str(timeout), ip], timeout=timeout + 1, cancelled=cancelled)
        if code == 0:
            outcome, code_label = 'up', 'echo_reply'
        elif code == 1:
            if any(value in output.lower() for value in (b'network is unreachable', b'no route to host', b'operation not permitted')):
                outcome, code_label = 'unknown', 'runner_network_unavailable'
            else:
                code_label = 'echo_timeout'
        else:
            outcome, code_label = 'unknown', 'icmp_unavailable'
    else:
        args = ['--unprivileged', '-sT', '-Pn', '-n', '-p', str(settings['port']), '--max-retries', '0',
                '--host-timeout', f'{timeout * 1000}ms', '--no-stylesheet', '-oX', '-']
        if ':' in ip:
            args.append('-6')
        code, output = run_utility('nmap', [*args, ip], timeout=timeout + 1, maximum=512 * 1024, cancelled=cancelled)
        if code:
            outcome, code_label = 'unknown', 'tcp_check_unavailable'
        else:
            records = parse_nmap(output, {ip})
            if any(settings['port'] in r['open_ports'] for r in records):
                outcome, code_label = 'up', 'tcp_port_open'
            else:
                code_label = 'tcp_port_not_open'
    return {'outcome': outcome, 'reason': code_label, 'address': ip, 'method': method,
            'latency_ms': round((time.monotonic() - start) * 1000, 2), **metadata}
