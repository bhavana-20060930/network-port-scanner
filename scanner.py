"""
Network Port Scanner
Author: Your Name
Description: A multithreaded TCP port scanner that identifies open ports,
             service names, and exports results to TXT or CSV reports.
"""

import socket
import csv
import threading
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# ──────────────────────────────────────────
# 1. SERVICE NAME LOOKUP
# ──────────────────────────────────────────
def get_service_name(port: int) -> str:
    """
    Return the well-known service name for a port number.
    Falls back to 'Unknown' if the port isn't registered.
    """
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "Unknown"


# ──────────────────────────────────────────
# 2. SINGLE PORT SCAN
# ──────────────────────────────────────────
def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict | None:
    """
    Attempt a TCP connection to ip:port.
    Returns a result dict if open, None if closed/filtered.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))   # 0 = success (port open)
            if result == 0:
                return {
                    "port":    port,
                    "status":  "OPEN",
                    "service": get_service_name(port),
                }
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return None


# ──────────────────────────────────────────
# 3. RANGE SCANNER (MULTITHREADED)
# ──────────────────────────────────────────
def scan_range(
    ip: str,
    start_port: int,
    end_port: int,
    timeout: float = 1.0,
    max_threads: int = 100,
) -> list[dict]:
    """
    Scan all ports from start_port to end_port (inclusive) using a
    thread pool so many ports are checked simultaneously.
    Returns a list of open-port dicts, sorted by port number.
    """
    open_ports: list[dict] = []
    lock = threading.Lock()                    # protects the shared list

    total = end_port - start_port + 1
    scanned = 0

    def _worker(port: int):
        nonlocal scanned
        result = scan_port(ip, port, timeout)
        with lock:
            scanned += 1
            # Simple progress indicator
            print(
                f"\r  Scanning port {port:5d} … "
                f"{scanned}/{total} done",
                end="",
                flush=True,
            )
            if result:
                open_ports.append(result)

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(_worker, port): port
            for port in range(start_port, end_port + 1)
        }
        for _ in as_completed(futures):
            pass   # progress already printed inside _worker

    print()   # newline after progress
    return sorted(open_ports, key=lambda r: r["port"])


# ──────────────────────────────────────────
# 4. REPORT GENERATION
# ──────────────────────────────────────────
def save_txt(results: list[dict], ip: str, filepath: str) -> None:
    """Write a human-readable TXT report."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(filepath, "w") as f:
        f.write("=" * 50 + "\n")
        f.write(f"  Network Port Scanner Report\n")
        f.write(f"  Target  : {ip}\n")
        f.write(f"  Scanned : {timestamp}\n")
        f.write("=" * 50 + "\n\n")

        if results:
            f.write(f"{'PORT':<10}{'STATUS':<12}{'SERVICE'}\n")
            f.write("-" * 35 + "\n")
            for r in results:
                f.write(f"{r['port']:<10}{r['status']:<12}{r['service']}\n")
        else:
            f.write("No open ports found.\n")

        f.write(f"\nTotal open ports: {len(results)}\n")
    print(f"  [+] TXT report saved → {filepath}")


def save_csv(results: list[dict], ip: str, filepath: str) -> None:
    """Write a machine-readable CSV report."""
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["port", "status", "service"])
        writer.writeheader()
        writer.writerows(results)
    print(f"  [+] CSV report saved → {filepath}")


# ──────────────────────────────────────────
# 5. CLI ENTRY POINT
# ──────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="🔍 Network Port Scanner — TCP port scanner with report export",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py 127.0.0.1
  python scanner.py 192.168.1.1 --start 1 --end 1024
  python scanner.py scanme.nmap.org --start 20 --end 100 --format csv
  python scanner.py 10.0.0.1 --threads 200 --timeout 0.5
        """,
    )
    parser.add_argument("ip",            help="Target IP address or hostname")
    parser.add_argument("--start",  "-s", type=int, default=1,    help="Start port (default: 1)")
    parser.add_argument("--end",    "-e", type=int, default=1024,  help="End port   (default: 1024)")
    parser.add_argument("--timeout","-t", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--threads","-T", type=int, default=100,   help="Max concurrent threads (default: 100)")
    parser.add_argument(
        "--format", "-f",
        choices=["txt", "csv", "both"],
        default="txt",
        help="Report format: txt | csv | both (default: txt)",
    )
    parser.add_argument("--output", "-o", default="scan_results", help="Output filename prefix (default: scan_results)")
    return parser.parse_args()


def main():
    args = parse_args()

    # Resolve hostname → IP
    try:
        resolved_ip = socket.gethostbyname(args.ip)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {args.ip}")
        return

    print("\n" + "=" * 50)
    print("  Network Port Scanner")
    print("=" * 50)
    print(f"  Target  : {args.ip} ({resolved_ip})")
    print(f"  Ports   : {args.start} – {args.end}")
    print(f"  Threads : {args.threads}")
    print(f"  Timeout : {args.timeout}s")
    print("=" * 50 + "\n")

    start_time = datetime.now()
    results = scan_range(
        ip=resolved_ip,
        start_port=args.start,
        end_port=args.end,
        timeout=args.timeout,
        max_threads=args.threads,
    )
    elapsed = (datetime.now() - start_time).total_seconds()

    # Print summary to console
    print(f"\n  Scan completed in {elapsed:.2f}s")
    print(f"  Open ports found: {len(results)}\n")

    if results:
        print(f"  {'PORT':<10}{'STATUS':<12}{'SERVICE'}")
        print("  " + "-" * 33)
        for r in results:
            print(f"  {r['port']:<10}{r['status']:<12}{r['service']}")
    else:
        print("  No open ports found in the given range.")

    # Save reports
    print()
    if args.format in ("txt", "both"):
        save_txt(results, resolved_ip, f"{args.output}.txt")
    if args.format in ("csv", "both"):
        save_csv(results, resolved_ip, f"{args.output}.csv")


if __name__ == "__main__":
    main()
