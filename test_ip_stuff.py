import socket

import dns.resolver, dns.reversename


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # doesn't have to be reachable
        s.connect(("10.254.254.254", 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = "127.0.0.1"
    finally:
        s.close()
    return IP


ip = get_ip()

canonical = dns.reversename.from_address(ip)
my_resolver = dns.resolver.Resolver()
try:
    answer = my_resolver.resolve(canonical, "PTR")
except dns.resolver.NXDOMAIN:
    print("Domain not found")
else:
    print(answer[0])
