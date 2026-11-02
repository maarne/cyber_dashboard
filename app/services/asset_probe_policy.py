"""Separate, scope-restricted asset-probe policy. Never relaxes outbound HTTP."""
import hashlib
import ipaddress
import json
import re
import socket

from app import config

PRIVATE = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'))
PLATFORM = {ipaddress.ip_address(v) for v in ('168.63.129.16', '169.254.169.254', '100.100.100.200', 'fd00:ec2::254')}


class ProbePolicyError(ValueError):
    pass


def address(value):
    if '%' in str(value):
        raise ProbePolicyError('Scoped addresses are not supported.')
    ip = ipaddress.ip_address(value)
    return ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip


def hostname(value):
    value = value.strip().rstrip('.')
    try:
        return str(address(value))
    except ValueError:
        if ':' in value or '%' in value:
            raise ProbePolicyError('Invalid target address.')
    try:
        result = value.encode('idna').decode('ascii').lower()
    except UnicodeError as exc:
        raise ProbePolicyError('Invalid hostname.') from exc
    if not result or len(result) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in result.split('.')):
        raise ProbePolicyError('Use one DNS hostname or IP, not a URL, command, or range.')
    # Reject alternative numeric representations instead of letting DNS/libc reinterpret them.
    if re.fullmatch(r'[0-9.]+', result) or result.startswith('0x'):
        raise ProbePolicyError('Use canonical IPv4 notation.')
    return result


def self_addresses():
    """Enumerate local interfaces without DNS or external socket connections (Linux)."""
    result = set()
    try:
        import fcntl
        import struct
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for _, name in socket.if_nameindex():
                try:
                    data = fcntl.ioctl(sock.fileno(), 0x8915, struct.pack('256s', name[:15].encode()))
                    result.add(address(socket.inet_ntoa(data[20:24])))
                except OSError:
                    pass
        from pathlib import Path
        for line in Path('/proc/net/if_inet6').read_text().splitlines():
            result.add(address(str(ipaddress.IPv6Address(int(line.split()[0], 16)))))
    except (OSError, ImportError):
        # Unsupported platforms must not silently lose the runner-self restriction.
        raise ProbePolicyError('Local interface policy inspection unavailable.')
    return result


def forbidden(ip, own):
    private = any(ip.version == n.version and ip in n for n in PRIVATE)
    return (ip in PLATFORM or ip in own or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_unspecified or ip.is_reserved or not (ip.is_global or private))


class ProbePolicy:
    def __init__(self):
        try:
            self.networks = [ipaddress.ip_network(v.strip()) for v in config.ASSET_PROBE_ALLOWED_CIDRS.split(',') if v.strip()]
        except ValueError as exc:
            raise ProbePolicyError('Invalid operator CIDR allowlist.') from exc
        if any(n.prefixlen == 0 for n in self.networks):
            raise ProbePolicyError('Universal network scopes are prohibited.')
        self.own = self_addresses()
        self.scope = config.ASSET_PROBE_SCOPE_LABEL
        self.fingerprint = hashlib.sha256(json.dumps([sorted(map(str, self.networks)), sorted(map(str, self.own)), self.scope]).encode()).hexdigest()

    def approve(self, value):
        try:
            ip = address(value)
        except ValueError as exc:
            raise ProbePolicyError('Invalid numeric address.') from exc
        broadcast = ip.version == 4 and any(n.version == 4 and n.prefixlen < 31 and ip == n.broadcast_address for n in self.networks)
        if forbidden(ip, self.own) or broadcast or not any(ip.version == n.version and ip in n for n in self.networks):
            raise ProbePolicyError('Destination is outside the authorized probe scope or is always prohibited.')
        return str(ip)

    def target(self, value, authorize=True):
        value = hostname(value)
        try:
            ip = address(value)
        except ValueError:
            if authorize and not self.networks:
                raise ProbePolicyError('An operator CIDR allowlist is required.')
            return value
        if forbidden(ip, self.own):
            raise ProbePolicyError('This destination is always prohibited.')
        return self.approve(str(ip)) if authorize else str(ip)

    def targets(self, networks, exclusions, authorize=True):
        try:
            nets = [ipaddress.ip_network(v) for v in networks]
            excluded = [ipaddress.ip_network(v) for v in exclusions]
        except ValueError as exc:
            raise ProbePolicyError('Use canonical network CIDRs or individual IP addresses.') from exc
        if authorize and any(not any(n.version == allowed.version and n.subnet_of(allowed) for allowed in self.networks) for n in nets):
            raise ProbePolicyError('Every complete network must be inside an operator-approved CIDR.')
        collapsed = [n for version in (4, 6) for n in ipaddress.collapse_addresses(n for n in nets if n.version == version)]
        if sum(n.num_addresses for n in collapsed) > 4096:
            raise ProbePolicyError('At most 4096 addresses per profile, checked before enumeration.')
        if any(not any(e.version == n.version and e.subnet_of(n) for n in nets) for e in excluded):
            raise ProbePolicyError('Exclusions must be inside the selected networks.')
        result = []
        for net in collapsed:
            for ip in net.hosts():
                if any(ip.version == e.version and ip in e for e in excluded):
                    continue
                if not forbidden(ip, self.own):
                    result.append(self.approve(str(ip)) if authorize else str(ip))
        if not result:
            raise ProbePolicyError('No authorized target addresses remain after exclusions/policy.')
        return result
