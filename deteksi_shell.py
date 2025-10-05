#!/usr/bin/env python3
"""
deteksi_shell.py

Deteksi nama-file shell (wso.php, cmd.php, shell.php, dll.) pada file log.
Output (ringkas): IP | file_shell | timestamp | http_code | keterangan (BERHASIL/GAGAL + kode)

Usage:
    python deteksi_shell.py -f access.log
    python deteksi_shell.py -f access.log -o hasil.csv
    python deteksi_shell.py -f access.log --shells wso.php,cmd.php,evil.php
"""
import re
import argparse
import csv
import sys
from urllib.parse import unquote

# Default daftar nama-file shell yang dicari (lowercase)
DEFAULT_SHELLS = {
    "wso.php", "cmd.php", "shell.php", "c99.php", "r57.php",
    "upload.php", "uploader.php", "backdoor.php", "downloader.php"
}

# Regex untuk format combined log: IP [timestamp] "METHOD PATH PROTO" STATUS ...
COMBINED_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'           # IP
    r'.*?\['
    r'(?P<time>[^\]]+)\]'                        # [timestamp]
    r'\s+"(?P<request>[^"]+)"\s+'                # "METHOD PATH HTTP/..."
    r'(?P<status>\d{3})'                         # status code
, re.IGNORECASE)

# fallback patterns
IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
FILENAME_RE = re.compile(r'([\w\-\.\%]+\.php)\b', re.IGNORECASE)

def parse_args():
    p = argparse.ArgumentParser(description="Deteksi upload/akses file shell dari log (IP, file, timestamp, http code, keterangan).")
    p.add_argument("-f", "--file", required=True, help="Path ke file log")
    p.add_argument("-o", "--out", help="Simpan hasil lengkap ke CSV")
    p.add_argument("--shells", help="Daftar file shell kustom, dipisah koma (mis. wso.php,cmd.php)")
    return p.parse_args()

def classify_by_status(status_code):
    """Return keterangan berdasarkan HTTP status code."""
    try:
        code = int(status_code)
    except:
        return f"GAGAL (kode tidak diketahui: {status_code})"
    if 200 <= code <= 299:
        return f"BERHASIL (HTTP {code})"
    else:
        return f"GAGAL (HTTP {code})"

def find_shells_in_path(path, shell_set):
    """Cari nama-file .php di path; kembalikan list nama-file yg match shell_set (lowercased)."""
    if not path:
        return []
    # decode percent-encoding agar 'wso%2Ephp' jadi 'wso.php'
    try:
        decoded = unquote(path)
    except:
        decoded = path
    found = []
    for m in FILENAME_RE.finditer(decoded):
        fname = m.group(1)
        if fname.lower() in shell_set:
            found.append(fname)
    return found

def analyze_line(line, shell_set):
    """
    Mencoba mengekstrak: ip, filename(s), timestamp, status.
    Mengembalikan list dict (bisa multiple file per baris).
    """
    results = []
    m = COMBINED_RE.search(line)
    if m:
        ip = m.group("ip")
        timestamp = m.group("time")
        request = m.group("request")  # e.g. GET /path/wso.php?x=1 HTTP/1.1
        status = m.group("status")
        # ambil path bagian tengah request
        parts = request.split()
        path = parts[1] if len(parts) >= 2 else ""
        shells = find_shells_in_path(path, shell_set)
        # If no shell in path, fallback: maybe filename appears elsewhere in line
        if not shells:
            for fm in FILENAME_RE.finditer(line):
                fq = fm.group(1)
                if fq.lower() in shell_set:
                    shells.append(fq)
        for fname in shells:
            results.append({
                "ip": ip,
                "file": fname,
                "timestamp": timestamp,
                "status": status
            })
        return results

    # fallback: tidak match combined -> cari filename dulu
    shells = []
    for fm in FILENAME_RE.finditer(line):
        fname = fm.group(1)
        if fname.lower() in shell_set:
            shells.append(fname)
    if shells:
        # coba ekstrak IP dan status bila ada
        ip = "-"
        status = "-"
        timestamp = "-"
        ip_m = IPV4_RE.search(line)
        if ip_m:
            ip = ip_m.group(0)
        # cari status code (any 3-digit) setelah request-like pattern atau di akhir
        s_m = re.search(r'"\s*(\d{3})\b', line)
        if s_m:
            status = s_m.group(1)
        else:
            # cari angka 3-digit manapun
            s2 = re.search(r'\b(\d{3})\b', line)
            if s2:
                status = s2.group(1)
        # timestamp: coba cari [..]
        t_m = re.search(r'\[([^\]]+)\]', line)
        if t_m:
            timestamp = t_m.group(1)
        for fname in shells:
            results.append({
                "ip": ip,
                "file": fname,
                "timestamp": timestamp,
                "status": status
            })
    return results

def run(file_path, out_csv=None, shells_extra=None):
    shell_set = set(DEFAULT_SHELLS)
    if shells_extra:
        for s in shells_extra.split(","):
            s = s.strip().lower()
            if s:
                shell_set.add(s)

    results = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                items = analyze_line(line, shell_set)
                for it in items:
                    it["keterangan"] = classify_by_status(it.get("status", "-"))
                    results.append(it)
    except FileNotFoundError:
        print(f"[!] File tidak ditemukan: {file_path}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"[!] Error saat membaca file: {e}", file=sys.stderr)
        sys.exit(3)

    # Print ringkas: IP | file | timestamp | status | keterangan
    if results:
        # dedup dan urutkan untuk tampilan rapi (urut berdasarkan ip,timestamp,file)
        unique = []
        seen = set()
        for r in results:
            key = (r["ip"], r["file"], r["timestamp"], r["status"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(r)
        unique = sorted(unique, key=lambda x: (x["ip"], x["timestamp"], x["file"]))
        print("=== HASIL DETEKSI SHELL (ringkas) ===")
        for r in unique:
            print(f"{r['ip']} | {r['file']} | {r['timestamp']} | {r['status']} | {r['keterangan']}")
    else:
        print("Tidak ditemukan nama-file shell pada log.")

    # Simpan ke CSV jika diminta
    if out_csv:
        try:
            with open(out_csv, "w", newline="", encoding="utf-8") as csvf:
                writer = csv.DictWriter(csvf, fieldnames=["ip","file","timestamp","status","keterangan"])
                writer.writeheader()
                for r in results:
                    writer.writerow({
                        "ip": r.get("ip","-"),
                        "file": r.get("file","-"),
                        "timestamp": r.get("timestamp","-"),
                        "status": r.get("status","-"),
                        "keterangan": r.get("keterangan","-")
                    })
            print(f"[+] Hasil lengkap disimpan ke {out_csv}")
        except Exception as e:
            print(f"[!] Gagal menulis CSV: {e}", file=sys.stderr)

    # exit code 1 jika ada indikasi (berguna utk automation)
    sys.exit(1 if results else 0)

if __name__ == "__main__":
    args = parse_args()
    run(args.file, out_csv=args.out, shells_extra=args.shells)
