import requests
import socket
import random
import string
import concurrent.futures
import re
from urllib.parse import urlparse

def generate_user_agent():
    return "Mozilla/5.0 (" + ''.join(random.choice(string.ascii_letters) for _ in range(8)) + ")"

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def brute_force_subdomains(domain, wordlist):
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(check_subdomain, f"{sub}.{domain}") for sub in wordlist]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
    return found

def check_subdomain(subdomain):
    try:
        headers = {"User-Agent": generate_user_agent()}
        resp = requests.get(f"http://{subdomain}", headers=headers, timeout=3, verify=False)
        if resp.status_code < 500:
            return subdomain
    except:
        return None

def bypass_waf_scan(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    payloads = ["", "/", "/?id=1", "/test"]
    for payload in payloads:
        try:
            headers = {"User-Agent": generate_user_agent()}
            requests.get(f"http://{domain}{payload}", headers=headers, timeout=3, verify=False)
        except:
            pass
    return True

def main(target):
    common_subs = ["www", "mail", "ftp", "ns1", "ns2", "blog", "dev", "api", "test", "home"]
    subdomains = brute_force_subdomains(target, common_subs)
    results = {}
    for sub in subdomains:
        ip = get_ip(sub)
        results[sub] = ip
        bypass_waf_scan(f"http://{sub}")
    return results

if __name__ == "__main__":
    target_domain = "example.com"
    data = main(target_domain)
    for sub, ip in data.items():
        print(f"{sub} - {ip}")
