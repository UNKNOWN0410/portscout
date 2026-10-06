"""
PortScout - a multithreaded TCP port scanner with host discovery,
banner grabbing, risk flagging and CSV/JSON reports.

Usage examples:
    python port_scanner.py 192.168.1.3
    python port_scanner.py 192.168.1.0/24 -p 22,80,443,445
    python port_scanner.py scanme.nmap.org -p 1-1000 --json report.json
    python port_scanner.py 192.168.1.22 -Pn --csv report.csv

Only scan hosts and networks you own or have permission to test.
"""
import argparse
import csv
import ipaddress
import json
import os
import platform
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

DEFAULT_PORTS = "1-1024,1433,3306,3389,5357,5432,5900,6379,8080,8443,27017"

COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 1433: "mssql", 3306: "mysql",
    3389: "rdp", 5357: "wsdapi", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}

# port -> (risk level, reason)
RISKY_PORTS = {
    21: ("HIGH", "FTP sends credentials in plaintext"),
    23: ("HIGH", "Telnet sends everything in plaintext"),
    135: ("MEDIUM", "Windows RPC, used in lateral movement"),
    139: ("MEDIUM", "NetBIOS, leaks host and share info"),
    445: ("HIGH", "SMB, target of WannaCry/EternalBlue"),
    1433: ("HIGH", "Database exposed to the network"),
    3306: ("HIGH", "Database exposed to the network"),
    3389: ("HIGH", "RDP, frequent brute-force target"),
    5432: ("HIGH", "Database exposed to the network"),
    5900: ("HIGH", "VNC, often weak or no password"),
    6379: ("HIGH", "Redis, often has no authentication"),
    27017: ("HIGH", "MongoDB, often has no authentication"),
    22: ("LOW", "SSH, safe if key-only and up to date"),
    80: ("LOW", "Unencrypted HTTP"),
}

# ANSI colours, only when writing to a real terminal (not a file or pipe).
# Enabled on Windows 10+ by the os.system("") call in main.
if sys.stdout.isatty():
    COLORS = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[96m"}
    GREEN, BOLD, RESET = "\033[92m", "\033[1m", "\033[0m"
else:
    COLORS = {"HIGH": "", "MEDIUM": "", "LOW": ""}
    GREEN = BOLD = RESET = ""


def parse_ports(spec):
    """Turn '22,80,100-200' into a sorted list of ints."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def parse_targets(target):
    """Accept a single IP, a hostname, or a CIDR range like 192.168.1.0/24."""
    if "/" in target:
        return [str(ip) for ip in ipaddress.ip_network(target, strict=False).hosts()]
    return [socket.gethostbyname(target)]


def is_host_up(ip, timeout_ms=800):
    """Host discovery with a single ICMP ping (like nmap -sn)."""
    if platform.system() == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    # Windows ping returns 0 even for "Destination host unreachable",
    # so also check that a real reply (TTL=) came back.
    return result.returncode == 0 and b"TTL=" in result.stdout.upper()


def scan_port(ip, port, timeout):
    """Full TCP connect scan: returns a result dict if open, else None."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) != 0:
            return None
        # Banner grabbing: many services (SSH, FTP, SMTP) announce themselves.
        try:
            banner = s.recv(1024).decode(errors="ignore").strip()
        except (socket.timeout, OSError):
            banner = ""
    risk, reason = RISKY_PORTS.get(port, ("", ""))
    return {
        "host": ip,
        "port": port,
        "service": COMMON_SERVICES.get(port, "unknown"),
        "banner": banner.splitlines()[0][:80] if banner else "",
        "risk": risk,
        "reason": reason,
    }


def scan_host(ip, ports, timeout, workers):
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: scan_port(ip, p, timeout), ports)
        return [r for r in results if r]


def print_host(ip, results):
    try:
        name = socket.gethostbyaddr(ip)[0]
    except OSError:
        name = ""
    print(f"\n{BOLD}{ip}{RESET} {name}")
    if not results:
        print("  no open ports found")
        return
    print(f"  {'PORT':<8}{'SERVICE':<14}{'RISK':<8}DETAILS")
    for r in results:
        color = COLORS.get(r["risk"], GREEN)
        details = r["banner"] or r["reason"]
        print(f"  {r['port']:<8}{r['service']:<14}{color}{r['risk'] or 'OK':<8}{RESET}{details}")


def save_json(path, meta, results):
    with open(path, "w") as f:
        json.dump({**meta, "results": results}, f, indent=2)


def save_csv(path, results):
    fields = ["host", "port", "service", "banner", "risk", "reason"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)


def main():
    parser = argparse.ArgumentParser(description="PortScout - TCP port scanner")
    parser.add_argument("target", help="IP, hostname or CIDR range (e.g. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="e.g. 22,80,1-1024")
    parser.add_argument("-t", "--timeout", type=float, default=0.5, help="seconds per port")
    parser.add_argument("-w", "--workers", type=int, default=200, help="parallel threads")
    parser.add_argument("-Pn", "--no-ping", action="store_true",
                        help="skip host discovery and scan every target")
    parser.add_argument("--json", metavar="FILE", help="save report as JSON")
    parser.add_argument("--csv", metavar="FILE", help="save report as CSV")
    args = parser.parse_args()

    os.system("")  # turns on ANSI colour support in the Windows console

    try:
        targets = parse_targets(args.target)
        ports = parse_ports(args.ports)
    except (socket.gaierror, ValueError) as e:
        print(f"Invalid target or ports: {e}")
        return

    start = datetime.now()
    print(f"{BOLD}PortScout{RESET} started {start:%Y-%m-%d %H:%M:%S}")
    print(f"Targets: {len(targets)} host(s), {len(ports)} port(s) each")

    if args.no_ping or len(targets) == 1:
        live = targets
    else:
        print("Discovering live hosts...")
        with ThreadPoolExecutor(max_workers=64) as pool:
            up = pool.map(is_host_up, targets)
            live = [ip for ip, alive in zip(targets, up) if alive]
        print(f"{len(live)} host(s) up: {', '.join(live)}")

    all_results = []
    for ip in live:
        results = scan_host(ip, ports, args.timeout, args.workers)
        print_host(ip, results)
        all_results.extend(results)

    elapsed = (datetime.now() - start).total_seconds()
    high = sum(1 for r in all_results if r["risk"] == "HIGH")
    print(f"\n{len(all_results)} open port(s) on {len(live)} host(s), "
          f"{COLORS['HIGH']}{high} high-risk{RESET}, in {elapsed:.2f}s")

    meta = {"target": args.target, "started": start.isoformat(),
            "duration_s": round(elapsed, 2), "hosts_up": live}
    if args.json:
        save_json(args.json, meta, all_results)
        print(f"JSON report saved to {args.json}")
    if args.csv:
        save_csv(args.csv, all_results)
        print(f"CSV report saved to {args.csv}")


if __name__ == "__main__":
    main()
