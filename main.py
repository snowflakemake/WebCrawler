#!/usr/bin/env python3

from scanner import scan_ip_range
import re

def run_scan(ip_range):
    sites = scan_ip_range(ip_range)
    if not sites:
        print("[-] No web servers found.")
        return
    print(f"[+] Found {len(sites)} web servers.")

    for site in sites:
        print(f"[~] Scanning {site}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Modular Web Vulnerability Scanner")
    parser.add_argument("ip_range", help="IP, IP range (CIDR) or domain")
    parser.add_argument("-p", "--ports", nargs="*", type=int, default=[80, 443, 8080, 8000, 8443, 5000, 8888],
                        help="List of ports to scan (default: 80, 443, 8080, 8000, 8443, 5000, 8888)")
    args = parser.parse_args()

    ip_regex = r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$"
    if re.match(r"^(w{3}\.)?[\w-]+(\.[\w-]+)+$", args.ip_range) and not re.match(ip_regex, args.ip_range):
        domainname = args.ip_range
        import socket
        domain_info = socket.getaddrinfo(domainname, None)
        print(f"[+] Domain info for {domainname}: {domain_info}")
        p = re.compile(f"({ip_regex})")
        result = p.search(str(domain_info)) # TODO: PROBLEM: This will not work as expected, need to extract IPs properly
        print(f"[+] Resolved domain {domainname} to IP: {result}")
        input()
    elif not re.match(ip_regex, args.ip_range):
        raise ValueError("Invalid IP range format. Use CIDR notation or ender a domain name.")
        

    run_scan(args.ip_range)
