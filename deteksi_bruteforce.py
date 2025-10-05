#!/usr/bin/env python3
import re
import argparse
from collections import defaultdict, Counter
from urllib.parse import unquote

# Regex log line (Apache/Nginx)
LOG_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(?P<path>[^\s"]+)',
    re.IGNORECASE
)

# Daftar endpoint login/bruteforce umum
LOGIN_ENDPOINTS = [
    "login", "admin", "wp-login.php", "signin", "cpanel", "administrator", "manager"
]

def parse_args():
    parser = argparse.ArgumentParser(description="Deteksi percobaan bruteforce dari log web.")
    parser.add_argument("-f", "--file", help="Path ke access log", required=True)
    return parser.parse_args()

def analyze_log(logfile):
    brute_data = defaultdict(lambda: defaultdict(Counter))
    
    with open(logfile, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = LOG_RE.search(line)
            if m:
                ip = m.group("ip")
                method = m.group("method").upper()
                path = unquote(m.group("path")).lower()
                for endpoint in LOGIN_ENDPOINTS:
                    if endpoint in path:
                        brute_data[ip][endpoint][method] += 1

    # Buat list untuk diurutkan berdasarkan total percobaan terbanyak
    sorted_list = []
    for ip, endpoints in brute_data.items():
        for endpoint, methods in endpoints.items():
            total = sum(methods.values())
            sorted_list.append((total, ip, endpoint, methods))

    # Urutkan descending berdasarkan total percobaan
    sorted_list.sort(reverse=True, key=lambda x: x[0])

    # Cetak hasil
    print(f"{'IP Address':<20} {'Target Endpoint':<25} {'Total Percobaan':<15} {'Metode HTTP'}")
    print("-"*80)
    for total, ip, endpoint, methods in sorted_list:
        method_summary = ", ".join([f"{m}:{c}" for m, c in methods.items()])
        print(f"{ip:<20} {endpoint:<25} {total:<15} {method_summary}")

def main():
    args = parse_args()
    analyze_log(args.file)

if __name__ == "__main__":
    main()

