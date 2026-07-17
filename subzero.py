#!/usr/bin/env python3
"""
SubZero — Comprehensive DNS Reconnaissance Tool
Requires: dnspython, colorama  (pip install dnspython colorama)
"""

import argparse
import concurrent.futures
import json
import os
import socket
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.reversename
import dns.zone
from colorama import Fore, Style, init

init(autoreset=True)

# ──────────────────────────── constants ─────────────────────────────────────

VERSION = "1.0.0"
DEFAULT_THREADS = 50
DEFAULT_TIMEOUT = 3.0
DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__), "subdomains.txt")

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV",
                "PTR", "DNSKEY", "DS", "NSEC", "CAA", "NAPTR"]

BANNER = f"""{Fore.CYAN}
   ██████╗██╗   ██╗██████╗ ███████╗███████╗██████╗  ██████╗
  ██╔════╝██║   ██║██╔══██╗╚══███╔╝██╔════╝██╔══██╗██╔═══██╗
  ╚█████╗ ██║   ██║██████╔╝   ███╔╝█████╗  ██████╔╝██║   ██║
   ╚═══██╗██║   ██║██╔══██╗  ███╔╝ ██╔══╝  ██╔══██╗██║   ██║
  ██████╔╝╚██████╔╝██████╔╝███████╗███████╗██║  ██║╚██████╔╝
  ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝
{Style.RESET_ALL}{Fore.WHITE}  SubZero v{VERSION}  |  Educational / Authorized Use Only
{Style.RESET_ALL}"""

# ──────────────────────────── helpers ───────────────────────────────────────

def info(msg: str)    -> None: print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}")
def ok(msg: str)      -> None: print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg: str)    -> None: print(f"{Fore.YELLOW}[-]{Style.RESET_ALL} {msg}")
def err(msg: str)     -> None: print(f"{Fore.RED}[!]{Style.RESET_ALL} {msg}")
def found(msg: str)   -> None: print(f"{Fore.GREEN}[FOUND]{Style.RESET_ALL} {msg}")
def section(title: str) -> None:
    print(f"\n{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  {title}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")


def build_resolver(nameserver: Optional[str], timeout: float) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.lifetime = timeout
    r.timeout  = timeout
    if nameserver:
        r.nameservers = [nameserver]
    return r


def fqdn(domain: str) -> str:
    return domain if domain.endswith(".") else domain + "."


def normalize_domain(raw: str) -> str:
    """Strip scheme, path, port and surrounding whitespace from user input.

    NOTE: str.lstrip("https://") must NOT be used for this — it strips any
    leading character in the set {h,t,p,s,:,/}, which silently eats the first
    letter of hosts like "shop.example.com" → "hop.example.com".
    """
    domain = raw.strip().lower()
    for scheme in ("https://", "http://"):
        if domain.startswith(scheme):
            domain = domain[len(scheme):]
            break
    domain = domain.split("/", 1)[0]   # drop any path
    domain = domain.split("?", 1)[0]   # drop any query string
    domain = domain.split("#", 1)[0]   # drop any fragment
    domain = domain.split("@", 1)[-1]  # drop any user-info prefix
    domain = domain.split(":", 1)[0]   # drop any :port
    return domain.strip(".")


# ──────────────────────────── data model ────────────────────────────────────

@dataclass
class DNSResult:
    domain:      str
    nameserver:  Optional[str]
    start_time:  str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    records:     dict = field(default_factory=dict)
    subdomains:  list = field(default_factory=list)
    zone_transfer: dict = field(default_factory=dict)
    wildcard:    Optional[bool] = None
    dnssec:      Optional[bool] = None
    reverse:     list = field(default_factory=list)


# ──────────────────────────── record enumeration ────────────────────────────

def query_record(resolver: dns.resolver.Resolver, domain: str, rtype: str) -> list[str]:
    try:
        answers = resolver.resolve(domain, rtype)
        return [r.to_text() for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.resolver.LifetimeTimeout):
        return []
    except Exception:
        return []


def enumerate_records(resolver: dns.resolver.Resolver, domain: str, result: DNSResult) -> None:
    section("DNS Record Enumeration")
    info(f"Target: {domain}")

    for rtype in RECORD_TYPES:
        answers = query_record(resolver, domain, rtype)
        if answers:
            result.records[rtype] = answers
            ok(f"{rtype:8s} → {answers[0]}")
            for extra in answers[1:]:
                print(f"           {extra}")

    # Explicit SPF / DMARC / DKIM pull from TXT
    _check_email_security(resolver, domain, result)

    if not result.records:
        warn("No records found — domain may not exist or be blocked.")


def _check_email_security(resolver: dns.resolver.Resolver, domain: str, result: DNSResult) -> None:
    specials = {
        "_dmarc":           f"_dmarc.{domain}",
        "DKIM (default)":   f"default._domainkey.{domain}",
        "DKIM (mail)":      f"mail._domainkey.{domain}",
    }
    for label, target in specials.items():
        answers = query_record(resolver, target, "TXT")
        if answers:
            result.records.setdefault("EMAIL_SECURITY", {})[label] = answers
            ok(f"EMAIL  {label:16s} → {answers[0][:80]}")


# ──────────────────────────── zone transfer ─────────────────────────────────

def attempt_zone_transfer(domain: str, result: DNSResult, timeout: float) -> None:
    section("Zone Transfer (AXFR)")

    ns_records = result.records.get("NS", [])
    if not ns_records:
        # Try to resolve NS directly
        try:
            r = dns.resolver.Resolver()
            r.timeout = timeout
            ns_records = [a.to_text() for a in r.resolve(domain, "NS")]
        except Exception:
            warn("No NS records — skipping zone transfer.")
            return

    for ns_raw in ns_records:
        ns = ns_raw.rstrip(".")
        info(f"Trying AXFR from {ns} …")
        try:
            ns_ip = socket.gethostbyname(ns)
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=timeout))
            names = sorted(z.nodes.keys())
            ok(f"Zone transfer SUCCESS from {ns} — {len(names)} records")
            result.zone_transfer[ns] = []
            for name in names:
                node_text = z[name].to_text(name)
                result.zone_transfer[ns].append(node_text)
                found(f"  {node_text}")
        except dns.exception.FormError:
            warn(f"  {ns} — AXFR refused / not supported")
        except (socket.gaierror, OSError) as e:
            warn(f"  {ns} — Cannot reach nameserver: {e}")
        except Exception as e:
            warn(f"  {ns} — {type(e).__name__}: {e}")


# ──────────────────────────── wildcard detection ────────────────────────────

def detect_wildcard(resolver: dns.resolver.Resolver, domain: str, result: DNSResult) -> None:
    section("Wildcard Detection")
    probe = f"wildcard-probe-{int(time.time())}.{domain}"
    answers = query_record(resolver, probe, "A")
    if answers:
        result.wildcard = True
        warn(f"Wildcard DNS detected → {answers[0]}  (subdomain results may be inflated)")
    else:
        result.wildcard = False
        ok("No wildcard record detected.")


# ──────────────────────────── DNSSEC ────────────────────────────────────────

def check_dnssec(resolver: dns.resolver.Resolver, domain: str, result: DNSResult) -> None:
    section("DNSSEC Check")
    dnskey = query_record(resolver, domain, "DNSKEY")
    ds     = query_record(resolver, domain, "DS")
    if dnskey:
        result.dnssec = True
        ok(f"DNSSEC ENABLED — {len(dnskey)} DNSKEY record(s) found.")
        if ds:
            ok(f"DS record(s) present — chain of trust established.")
    else:
        result.dnssec = False
        warn("DNSSEC NOT enabled — no DNSKEY record.")


# ──────────────────────────── subdomain brute-force ─────────────────────────

def _probe_subdomain(args) -> Optional[tuple[str, list[str]]]:
    sub, domain, resolver_ns, timeout = args
    target = f"{sub}.{domain}"
    resolver = build_resolver(resolver_ns, timeout)
    answers = query_record(resolver, target, "A")
    if not answers:
        answers = query_record(resolver, target, "AAAA")
    return (target, answers) if answers else None


def brute_subdomains(domain: str, wordlist_path: str, result: DNSResult,
                     nameserver: Optional[str], timeout: float, threads: int) -> None:
    section("Subdomain Brute-Force")

    if not os.path.isfile(wordlist_path):
        warn(f"Wordlist not found: {wordlist_path}")
        warn("Generating built-in minimal wordlist …")
        words = _builtin_wordlist()
    else:
        with open(wordlist_path, "r", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    info(f"Wordlist: {len(words)} entries  |  threads: {threads}")

    tasks = [(w, domain, nameserver, timeout) for w in words]
    found_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_probe_subdomain, t): t for t in tasks}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                fqdn_host, ips = res
                result.subdomains.append({"host": fqdn_host, "ips": ips})
                found(f"{fqdn_host:<45} {', '.join(ips)}")
                found_count += 1

    if found_count:
        ok(f"Found {found_count} subdomain(s).")
    else:
        warn("No subdomains discovered.")


def _builtin_wordlist() -> list[str]:
    return [
        "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
        "smtp", "secure", "vpn", "m", "shop", "ftp", "api", "dev", "staging",
        "admin", "portal", "cdn", "test", "app", "git", "gitlab", "github",
        "jira", "confluence", "jenkins", "ci", "beta", "prod", "production",
        "qa", "uat", "db", "database", "mysql", "mongo", "redis", "elastic",
        "elk", "grafana", "prometheus", "kibana", "ldap", "auth", "sso",
        "login", "mx", "mx1", "mx2", "imap", "pop", "pop3", "exchange",
        "autodiscover", "docs", "help", "support", "status", "monitor",
        "intranet", "internal", "old", "new", "v2", "static", "assets",
        "media", "img", "images", "upload", "files", "download",
    ]


# ──────────────────────────── reverse lookup ────────────────────────────────

def reverse_lookups(ips: list[str], result: DNSResult, timeout: float) -> None:
    if not ips:
        return
    section("Reverse DNS Lookups")
    resolver = build_resolver(None, timeout)
    for ip in ips:
        try:
            rev = dns.reversename.from_address(ip)
            answers = resolver.resolve(rev, "PTR")
            ptr = answers[0].to_text()
            ok(f"{ip:20s} → {ptr}")
            result.reverse.append({"ip": ip, "ptr": ptr})
        except Exception:
            warn(f"{ip:20s} → no PTR record")


# ──────────────────────────── SOA / whois info ──────────────────────────────

def print_soa_detail(result: DNSResult) -> None:
    soa_list = result.records.get("SOA")
    if not soa_list:
        return
    soa = soa_list[0]
    parts = soa.split()
    section("SOA Detail")
    labels = ["Primary NS", "Responsible", "Serial", "Refresh", "Retry", "Expire", "Min TTL"]
    for label, val in zip(labels, parts):
        info(f"  {label:15s}: {val}")


# ──────────────────────────── output ────────────────────────────────────────

def save_output(result: DNSResult, path: str, fmt: str) -> None:
    if fmt == "json":
        data = {
            "domain":       result.domain,
            "nameserver":   result.nameserver,
            "start_time":   result.start_time,
            "wildcard":     result.wildcard,
            "dnssec":       result.dnssec,
            "records":      result.records,
            "subdomains":   result.subdomains,
            "zone_transfer":result.zone_transfer,
            "reverse":      result.reverse,
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    else:  # text
        with open(path, "w") as f:
            f.write(f"DNS Enumeration Report — {result.domain}\n")
            f.write(f"Generated: {result.start_time}\n\n")
            f.write("=== Records ===\n")
            for rtype, vals in result.records.items():
                if isinstance(vals, list):
                    for v in vals:
                        f.write(f"{rtype:10s}  {v}\n")
                elif isinstance(vals, dict):
                    for k, v in vals.items():
                        f.write(f"{rtype}/{k:10s}  {v}\n")
            f.write("\n=== Subdomains ===\n")
            for sd in result.subdomains:
                f.write(f"{sd['host']}  {', '.join(sd['ips'])}\n")
            if result.zone_transfer:
                f.write("\n=== Zone Transfer ===\n")
                for ns, records in result.zone_transfer.items():
                    f.write(f"[{ns}]\n")
                    for r in records:
                        f.write(f"  {r}\n")
    ok(f"Results saved → {path}")


# ──────────────────────────── summary ───────────────────────────────────────

def print_summary(result: DNSResult, elapsed: float) -> None:
    section("Summary")
    a_ips = result.records.get("A", [])
    print(f"  Domain          : {result.domain}")
    print(f"  IP(s)           : {', '.join(a_ips) if a_ips else 'n/a'}")
    print(f"  Record types    : {len(result.records)}")
    print(f"  Subdomains found: {len(result.subdomains)}")
    print(f"  Zone transfer   : {'YES (' + str(len(result.zone_transfer)) + ' NS)' if result.zone_transfer else 'No'}")
    print(f"  Wildcard        : {'Yes' if result.wildcard else 'No'}")
    print(f"  DNSSEC          : {'Enabled' if result.dnssec else 'Disabled'}")
    print(f"  Elapsed         : {elapsed:.2f}s")
    print()


# ──────────────────────────── CLI ───────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="subzero",
        description="SubZero — Comprehensive DNS Enumeration Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Examples:\n"
               "  %(prog)s example.com\n"
               "  %(prog)s example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt\n"
               "  %(prog)s example.com --no-brute --output report.json --format json\n"
               "  %(prog)s example.com -n 8.8.8.8 --threads 100 --reverse\n"
    )
    p.add_argument("domain",                 help="Target domain (e.g. example.com)")
    p.add_argument("-n", "--nameserver",     metavar="IP",    help="Use custom nameserver (default: system)")
    p.add_argument("-w", "--wordlist",       metavar="FILE",  default=DEFAULT_WORDLIST, help="Subdomain wordlist path")
    p.add_argument("-t", "--threads",        type=int,        default=DEFAULT_THREADS,  help=f"Thread count (default: {DEFAULT_THREADS})")
    p.add_argument("--timeout",             type=float,      default=DEFAULT_TIMEOUT,  help=f"Query timeout seconds (default: {DEFAULT_TIMEOUT})")
    p.add_argument("--no-brute",            action="store_true", help="Skip subdomain brute-force")
    p.add_argument("--no-zone",             action="store_true", help="Skip zone transfer attempt")
    p.add_argument("--no-dnssec",           action="store_true", help="Skip DNSSEC check")
    p.add_argument("--reverse",             action="store_true", help="Perform reverse PTR lookups on discovered IPs")
    p.add_argument("-o", "--output",        metavar="FILE",  help="Save results to file")
    p.add_argument("-f", "--format",        choices=["text", "json"], default="text", help="Output format (default: text)")
    return p.parse_args()


# ──────────────────────────── main ──────────────────────────────────────────

def main() -> None:
    print(BANNER)
    args = parse_args()

    domain = normalize_domain(args.domain)
    resolver = build_resolver(args.nameserver, args.timeout)
    result   = DNSResult(domain=domain, nameserver=args.nameserver)

    info(f"Target         : {domain}")
    info(f"Nameserver     : {args.nameserver or 'system default'}")
    info(f"Threads        : {args.threads}")
    info(f"Timeout        : {args.timeout}s")

    start = time.time()

    # 1. Record enumeration (always)
    enumerate_records(resolver, domain, result)
    print_soa_detail(result)

    # 2. Wildcard detection
    detect_wildcard(resolver, domain, result)

    # 3. DNSSEC
    if not args.no_dnssec:
        check_dnssec(resolver, domain, result)

    # 4. Zone transfer
    if not args.no_zone:
        attempt_zone_transfer(domain, result, args.timeout)

    # 5. Subdomain brute-force
    if not args.no_brute:
        brute_subdomains(domain, args.wordlist, result,
                         args.nameserver, args.timeout, args.threads)

    # 6. Reverse lookups
    if args.reverse:
        all_ips = result.records.get("A", []) + result.records.get("AAAA", [])
        all_ips += [sd["ips"][0] for sd in result.subdomains if sd["ips"]]
        reverse_lookups(list(dict.fromkeys(all_ips)), result, args.timeout)

    elapsed = time.time() - start
    print_summary(result, elapsed)

    if args.output:
        save_output(result, args.output, args.format)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)
