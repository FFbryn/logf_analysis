import re
import argparse

# Daftar file penting yang ingin dipantau
CRITICAL_FILES = [
    r'\.env',
    r'config\.php',
    r'database\.sql',
    r'wp-config\.php',
    r'\.htpasswd',
    r'\.ssh/id_rsa',
    r'\.git/config'
]

# Fungsi untuk mendeteksi file penting
def is_critical(file_path):
    for pattern in CRITICAL_FILES:
        if re.search(pattern, file_path, re.IGNORECASE):
            return True
    return False

# Fungsi untuk membaca log dan filter download file penting yang BERHASIL
def parse_log(file_path):
    results = []
    log_pattern = re.compile(
        r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - - '
        r'\[(?P<datetime>[^\]]+)\] '
        r'"(?P<method>GET|POST) (?P<endpoint>[^ ]+) HTTP/[0-9.]+" '
        r'(?P<status>\d{3})'
    )

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            match = log_pattern.search(line)
            if match:
                ip = match.group('ip')
                dt = match.group('datetime')
                method = match.group('method')
                endpoint = match.group('endpoint')
                status = match.group('status')
                
                # Hanya ambil yang BERHASIL (HTTP 2xx)
                if is_critical(endpoint) and status.startswith('2'):
                    results.append({
                        'ip': ip,
                        'file': endpoint,
                        'datetime': dt,
                        'method': method,
                        'status': status,
                        'keterangan': f"BERHASIL (HTTP {status})"
                    })
    return results

# Fungsi untuk menampilkan hasil
def print_results(results):
    if not results:
        print("Tidak ada download file penting yang BERHASIL terdeteksi.")
        return

    print(f"{'IP Address':<20} {'File':<25} {'Tanggal & Waktu':<30} {'Metode':<6} {'Status':<6} {'Keterangan'}")
    print("-"*100)
    for r in results:
        print(f"{r['ip']:<20} {r['file']:<25} {r['datetime']:<30} {r['method']:<6} {r['status']:<6} {r['keterangan']}")

# Main program
def main():
    parser = argparse.ArgumentParser(description="Deteksi download file penting BERHASIL di server")
    parser.add_argument('-f', '--file', required=True, help='Path file log server')
    args = parser.parse_args()

    results = parse_log(args.file)
    print_results(results)

if __name__ == "__main__":
    main()
