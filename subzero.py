import dns.resolver
import dns.zone
import dns.query
import dns.reversename
import threading
import queue
import json
from colorama import Fore, Style, init

init(autoreset=True)

# Wordlist simple pour la brute force de sous-domaines (à enrichir)
WORDLIST = [
    'www', 'mail', 'ftp', 'webmail', 'smtp', 'ns1', 'ns2', 
    'admin', 'test', 'portal', 'secure', 'vpn', 'blog', 
    'dev', 'api', 'm', 'shop', 'home'
]

class DNSEnumerator:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = []
        self.subdomain_results = {}
        self.lock = threading.Lock()
        self.queue = queue.Queue()
        self.resolver = dns.resolver.Resolver()
        self.results = {
            "A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [],
            "SOA": [], "TXT": [], "ZoneTransfer": False,
            "ZoneTransferData": None,
            "Subdomains": {}
        }
    
    def query_dns_record(self, record_type):
        try:
            answers = self.resolver.resolve(self.domain, record_type)
            for rdata in answers:
                self.results[record_type].append(str(rdata))
            print(f"{Fore.GREEN}[+] {record_type} records found:")
            for r in self.results[record_type]:
                print(f"  {Fore.CYAN}{r}")
        except dns.resolver.NoAnswer:
            print(f"{Fore.YELLOW}[-] No {record_type} record found.")
        except dns.resolver.NXDOMAIN:
            print(f"{Fore.RED}[-] Domain does not exist.")
        except Exception as e:
            print(f"{Fore.RED}[-] Error querying {record_type}: {e}")
    
    def try_zone_transfer(self):
        try:
            ns_records = self.resolver.resolve(self.domain, 'NS')
            for ns in ns_records:
                ns = str(ns.target).rstrip('.')
                print(f"{Fore.BLUE}[*] Trying zone transfer from {ns} ...")
                zone = dns.zone.from_xfr(dns.query.xfr(ns, self.domain, lifetime=5))
                if zone:
                    self.results["ZoneTransfer"] = True
                    zone_data = []
                    for name, node in zone.nodes.items():
                        rdatasets = node.rdatasets
                        for rdataset in rdatasets:
                            for rdata in rdataset:
                                zone_data.append(f"{name.to_text()} {rdataset.rdtype} {rdata.to_text()}")
                    self.results["ZoneTransferData"] = zone_data
                    print(f"{Fore.GREEN}[+] Zone transfer successful! Got {len(zone_data)} records.")
                    return
            print(f"{Fore.YELLOW}[-] Zone transfer not allowed or failed.")
        except Exception as e:
            print(f"{Fore.RED}[-] Zone transfer error: {e}")
    
    def reverse_dns_lookup(self, ip):
        try:
            addr = dns.reversename.from_address(ip)
            answer = self.resolver.resolve(addr, 'PTR')
            return str(answer[0])
        except Exception:
            return None
    
    def worker(self):
        while not self.queue.empty():
            sub = self.queue.get()
            try:
                fullname = f"{sub}.{self.domain}"
                answers = self.resolver.resolve(fullname, 'A')
                ips = [str(rdata) for rdata in answers]
                with self.lock:
                    self.results["Subdomains"][fullname] = ips
                print(f"{Fore.GREEN}[+] {fullname} -> {ips}")
            except Exception:
                pass
            self.queue.task_done()
    
    def brute_force_subdomains(self):
        print(f"{Fore.BLUE}[*] Starting brute force subdomain enumeration...")
        for sub in WORDLIST:
            self.queue.put(sub)
        thread_count = 10
        threads = []
        for _ in range(thread_count):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        self.queue.join()
    
    def enumerate(self):
        print(f"{Fore.MAGENTA}== DNS Enumeration for {self.domain} ==")
        for rtype in ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT']:
            self.query_dns_record(rtype)
        self.try_zone_transfer()
        self.brute_force_subdomains()
        print(f"{Fore.MAGENTA}== Enumeration Complete ==")
    
    def save_results(self, filename='dns_enum_results.json'):
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        print(f"{Fore.GREEN}[+] Results saved to {filename}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: python dns_enum_megacomplet.py <domain>")
        sys.exit(1)
    domain = sys.argv[1].strip()
    enumerator = DNSEnumerator(domain)
    enumerator.enumerate()
    enumerator.save_results()

