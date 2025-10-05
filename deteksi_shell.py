#!/usr/bin/env python3
"""
deteksi_shell.py — by Surya

Mendeteksi aktivitas upload (POST) dan eksekusi (GET) PHP shell dari file log webserver.

Output:
IP | file_shell | timestamp | method | status_code | keterangan (UPLOAD / EKSEKUSI + berhasil/gagal)

Contoh:
python deteksi_shell.py -f access.log
python deteksi_shell.py -f access.log -o hasil.csv
"""

import re
import argparse
import csv
import sys
from urllib.parse import unquote

# === Daftar nama file shell umum ===
DEFAULT_SHELLS = {
    "wso.php", "cmd.php", "shell.php", "c99.php", "r57.php",
    "upload.php", "uploader.php", "backdoor.php", "evil.php"
}

# === Regex format log Apache/Nginx combined ===
COMBINED_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'           # IP
    r'.*?\['
    r'(?P<time>[^\]]+)\]'                        # timestamp
    r'\s+"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(?P<path>[^"\s]+)[^"]*"\s+'
    r'(?P<status>\d{3})',                        # status code
    re.IGNORECASE
)

# === Fallback pattern ===
IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
FILENAME_RE = re.compile(r'([\w\-\.\%]+\.php)\b', re.IGNORECASE)


def parse_args():
    p = argparse.ArgumentParser(description="Deteksi upload & eksekusi PHP shell dari file log.")
    p.add_argument("-f", "--file", required=True, help="Path ke file log (mis. access.log)")
    p.add_argument("-o", "--out", help="Simpan hasil ke file CSV")
    p.add_argument("--shells", help="Tambah daftar file shell (mis. wso.php,cmd.php)")
    return p.parse_args()


def classify_status(code):
    """Ubah kode HTTP jadi keterangan sederhana."""
    try:
        c = int(code)
    except:
        return "Kode tidak valid"
    if 200 <= c <= 299:
        return f"BERHASIL (HTTP {c})"
    elif c == 404:
        return f"TIDAK DITEMUKAN (HTTP {c})"
    elif c == 403:
        return f"DITOLAK (HTTP {c})"
    elif c == 500:
        return f"SERVER ERROR (HTTP {c})"
    else:
        return f"GAGAL (HTTP {c})"


def find_shell(path, shell_set):
    """Cari file shell di path (decode %)."""
    if not path:
        return []
    try:
        decoded = unquote(path)
    except:
        decoded = path
    found = []
    for match in FILENAME_RE.finditer(decoded):
        f = match.group(1).lower()
        if f in shell_set:
            found.append(f)
    return found


def parse_line(line, shell_set):
    """Ambil data dari 1 baris log."""
    result = []
    m = COMBINED_RE.search(line)
    if m:
        ip = m.group("ip")
        timestamp = m.group("time")
        method = m.group("method").upper()
        path = m.group("path")
        status = m.group("status")
        shells = find_shell(path, shell_set)

        for s in shells:
            jenis = "UPLOAD" if method == "POST" else "EKSEKUSI" if method == "GET" else "LAINNYA"
            result.append({
                "ip": ip,
                "file": s,
                "timestamp": timestamp,
                "method": method,
                "status": status,
                "keterangan": f"{jenis} - {classify_status(status)}"
            })
    return result


def run(file_path, out_csv=None, shells_extra=None):
    shell_set = set(DEFAULT_SHELLS)
    if shells_extra:
        for s in shells_extra.split(","):
            s = s.strip().lower()
            if s:
                shell_set.add(s)

    hasil = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                hasil += parse_line(line, shell_set)
    except FileNotFoundError:
        print(f"[!] File tidak ditemukan: {file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Kesalahan: {e}")
        sys.exit(2)

    if hasil:
        print("=== HASIL DETEKSI UPLOAD & EKSEKUSI SHELL ===")
        for h in hasil:
            print(f"{h['ip']} | {h['file']} | {h['timestamp']} | {h['method']} | {h['status']} | {h['keterangan']}")
    else:
        print("Tidak ditemukan aktivitas upload atau eksekusi shell.")

    if out_csv:
        try:
            with open(out_csv, "w", newline="", encoding="utf-8") as csvf:
                writer = csv.DictWriter(csvf, fieldnames=["ip","file","timestamp","method","status","keterangan"])
                writer.writeheader()
                writer.writerows(hasil)
            print(f"[+] Hasil disimpan ke {out_csv}")
        except Exception as e:
            print(f"[!] Gagal menulis CSV: {e}")


if __name__ == "__main__":
    args = parse_args()
    run(args.file, args.out, args.shells)
