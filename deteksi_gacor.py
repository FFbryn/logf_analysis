#!/usr/bin/env python3
import re
import argparse
from urllib.parse import unquote

# Regex log line (Apache/Nginx)
LOG_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?\[(?P<time>[^\]]+)\]\s+"(?P<method>GET|POST)\s+(?P<path>[^\s"]+)[^"]*"\s+(?P<status>\d{3})',
    re.IGNORECASE
)

def parse_args():
    parser = argparse.ArgumentParser(description="Deteksi file gacor.html di log dan filesystem.")
    parser.add_argument("-f", "--file", help="Path ke access log", required=True)
    return parser.parse_args()

def analyze_log(logfile):
    with open(logfile, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = LOG_RE.search(line)
            if m:
                ip = m.group("ip")
                timestamp = m.group("time")
                method = m.group("method").upper()
                path = unquote(m.group("path"))
                status = m.group("status")
                if "gacor.html" in path.lower():
                    # keterangan status
                    status_desc = f"BERHASIL (HTTP {status})" if status.startswith("2") else f"GAGAL (HTTP {status})"
                    print(f"{ip} | gacor.html | {timestamp} | {method} | {status} | {status_desc}")

def main():
    args = parse_args()
    analyze_log(args.file)

if __name__ == "__main__":
    main()
