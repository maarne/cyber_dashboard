"""Exercise real utility adapters ONLY on disposable container loopback.

The container has --network none, no mounted user data, no authorized real
networks and no production policy exception. This directly tests private
adapters against a fixture server; the application's policy still denies self.
"""
import os
import secrets
import subprocess
import sys

FIXTURE = r'''
import json, os, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from app.services import asset_probe_service as probes

assert os.getuid() == 10001
assert not (os.stat('/usr/bin/ping').st_mode & 0o6000)
assert 'security.capability' not in os.listxattr('/usr/bin/ping')

class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200); self.send_header('Content-Length','0'); self.end_headers()
    def log_message(self, *args):
        pass

class FixtureServer(HTTPServer):
    def handle_error(self, request, client_address):
        pass  # Expected TCP discovery connect/reset is not an HTTP request.

server = FixtureServer(('127.0.0.1',0), Handler)
thread = threading.Thread(target=server.serve_forever,daemon=True); thread.start()
port = server.server_port
settings = dict(target='127.0.0.1',method='http',port=port,http_method='HEAD',path='/',expected_codes=[200],timeout_seconds=2)
try:
    http = probes.check(settings,'127.0.0.1')
    assert http['outcome']=='up', http
    tcp = probes.check({**settings,'method':'tcp'},'127.0.0.1')
    assert tcp['outcome']=='up', tcp
    discovery = probes.discover(['127.0.0.1'],dict(ports=[port],timeout_seconds=2))
    assert len(discovery)==1, discovery
    icmp = probes.check({**settings,'method':'icmp'},'127.0.0.1')
    assert icmp['outcome'] in ('up','unknown'), icmp
    versions = {}
    for utility, flag in (('curl','--version'),('nmap','--version'),('ping','-V')):
        code, output = probes.run_utility(utility,[flag],timeout=4)
        assert code==0, (utility,code)
        versions[utility]=output.decode(errors='replace').splitlines()[0]
    print(json.dumps(dict(non_root=True,no_ping_file_capability=True,network='none / fixture loopback only',
                         http=http['outcome'],tcp=tcp['outcome'],discovery_responses=len(discovery),icmp=icmp['outcome'],versions=versions),indent=2))
finally:
    server.shutdown(); server.server_close(); thread.join(timeout=2)
'''


if __name__ == '__main__':
    image = sys.argv[1] if len(sys.argv) > 1 else 'cyberdash:asset-network'
    env = {**os.environ, 'JWT_SECRET_KEY': secrets.token_hex(32)}
    subprocess.run(['docker', 'run', '--rm', '--network', 'none', '-i', '-e', 'JWT_SECRET_KEY', '--entrypoint', 'python', image, '-B', '-'],
                   input=FIXTURE, text=True, env=env, check=True)
