import dns.resolver
import socket
import requests

subdomains = [
    "www", "mail", "ftp", "remote", "cpanel", "webmail", "smtp", "ns1", "ns2",
    "admin", "portal", "vpn", "home", "router", "office", "server", "dev"
]

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def brute_force(domain):
    results = {}
    for sub in subdomains:
        full = f"{sub}.{domain}"
        ip = get_ip(full)
        if ip:
            results[full] = ip
    return results

def resolve_dns(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [rdata.address for rdata in answers]
    except:
        return []

def get_real_ip_from_headers(domain):
    try:
        r = requests.get(f"http://{domain}", timeout=5)
        headers = r.headers
        return headers.get('X-Forwarded-For') or headers.get('CF-Connecting-IP') or "No header IP"
    except:
        return "Request failed"

def main(target_domain):
    print(f"[*] Resolving A records for {target_domain}")
    ips = resolve_dns(target_domain)
    for ip in ips:
        print(f" -> Found IP: {ip}")

    print(f"\n[*] Brute-forcing subdomains on {target_domain}")
    subs = brute_force(target_domain)
    for s, ip in subs.items():
        print(f" -> {s} -> {ip}")

    print(f"\n[*] Trying to find real IP through headers...")
    real_ip = get_real_ip_from_headers(target_domain)
    print(f" -> Real IP from headers: {real_ip}")

if __name__ == "__main__":
    target = input("Enter target domain: ")
    main(target)
