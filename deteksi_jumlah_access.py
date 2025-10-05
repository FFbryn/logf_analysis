#!/usr/bin/env python3
import re
import argparse
from collections import defaultdict, Counter

# Regex log line (Apache/Nginx)
LOG_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(?P<path>[^\s"]+)',
    re.IGNORECASE
)

def parse_args():
    parser = argparse.ArgumentParser(description="Deteksi IP yang paling banyak mengakses log.")
    parser.add_argument("-f", "--file", help="Path ke access log", required=True)
    return parser.parse_args()

def analyze_log(logfile):
    ip_count = defaultdict(lambda: Counter())
    with open(logfile, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = LOG_RE.search(line)
            if m:
                ip = m.group("ip")
                method = m.group("method").upper()
                ip_count[ip][method] += 1

    # Urutkan berdasarkan total akses terbanyak
    sorted_ips = sorted(ip_count.items(), key=lambda x: sum(x[1].values()), reverse=True)
    
    print(f"{'IP Address':<20} {'Total Akses':<12} {'Metode HTTP'}")
    print("-"*60)
    for ip, methods in sorted_ips:
        total = sum(methods.values())
        method_summary = ", ".join([f"{m}:{c}" for m, c in methods.items()])
        print(f"{ip:<20} {total:<12} {method_summary}")

def main():
    args = parse_args()
    analyze_log(args.file)

if __name__ == "__main__":
    main()
