"""Private subprocess launcher: resource limits apply before exec, never preexec_fn."""
import json
import os
import resource
import socket
import sys


def main():
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    mode, value = sys.argv[1:3]
    if mode == 'exec':
        args = json.loads(value)
        if args[0] not in ('/usr/bin/curl', '/bin/curl', '/usr/bin/ping', '/bin/ping', '/usr/bin/nmap', '/bin/nmap'):
            raise ValueError('Unsupported executable')
        os.execve(args[0], args, dict(os.environ))
    elif mode == 'resolve':
        values = sorted({info[4][0] for info in socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)})
        if not 1 <= len(values) <= 8:
            raise ValueError('DNS answer limit')
        print(json.dumps(values))
    elif mode == 'reverse':
        name, aliases, _ = socket.gethostbyaddr(value)
        print(json.dumps([name, *aliases][:8]))
    else:
        raise ValueError('Unsupported operation')


if __name__ == '__main__':
    main()
