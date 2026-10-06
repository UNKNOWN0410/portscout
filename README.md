# PortScout – Network Port Scanner

A multithreaded TCP port scanner written in pure Python (no external libraries).
It discovers live hosts on a network, finds open ports, grabs service banners,
flags risky services and exports reports.

> ⚠️ Only scan systems you own or have written permission to test.

## Features
| Feature | How it works |
|---|---|
| Host discovery | Parallel ICMP ping sweep (like `nmap -sn`) |
| Port scanning | TCP connect scan with `socket.connect_ex()` (like `nmap -sT`) |
| Speed | `ThreadPoolExecutor` scans 200 ports in parallel |
| Banner grabbing | Reads the first bytes a service sends to reveal software and version |
| Risk flagging | Marks dangerous services (Telnet, FTP, SMB, RDP, open databases) as HIGH/MEDIUM/LOW |
| Reports | Exports results to JSON and CSV |
| Targets | Single IP, hostname or CIDR range (`192.168.1.0/24`) |

## Usage
```
python port_scanner.py <target> [options]

  -p, --ports     ports to scan, e.g. 22,80,1-1024   (default: 1-1024 + common high ports)
  -t, --timeout   seconds to wait per port           (default: 0.5)
  -w, --workers   parallel threads                   (default: 200)
  -Pn             skip ping discovery, scan every host
  --json FILE     save report as JSON
  --csv FILE      save report as CSV
```

### Examples
```
python port_scanner.py 10.10.10.5
python port_scanner.py 10.10.10.0/24 --csv report.csv
python port_scanner.py 10.10.10.5 -p 1-65535 -w 500
```

## How it works
1. **Target parsing:** `ipaddress.ip_network()` expands a CIDR range into host IPs.
2. **Host discovery:** each host is pinged in parallel; only hosts that reply are scanned.
   Hosts that block ping can still be scanned with `-Pn`.
3. **TCP connect scan:** for each port the scanner attempts the 3-way handshake
   (`SYN → SYN-ACK → ACK`). `connect_ex()` returning `0` means the port is **open**.
4. **Banner grabbing:** after connecting, it waits briefly for the service to send a greeting
   (e.g. `SSH-2.0-OpenSSH_10.4p1`). Version strings can be matched against known CVEs.
5. **Risk assessment:** open ports are checked against a table of commonly exploited services.

## Sample output
Scanning my own lab machines (a Raspberry Pi running Kali and an intentionally weak test VM):
```
10.10.10.5 lab-vm
  PORT    SERVICE       RISK    DETAILS
  21      ftp           HIGH    220 (vsFTPd 2.3.4)
  23      telnet        HIGH    Telnet sends everything in plaintext
  80      http          LOW     Unencrypted HTTP

10.10.10.3 kali-pi
  22      ssh           LOW     SSH-2.0-OpenSSH_10.4p1 Debian-5
```

## Limitations and future work
- Connect scans are logged by the target; a SYN (half-open) scan needs raw sockets and admin rights (e.g. with Scapy).
- UDP ports are not scanned.
- Could add: OS fingerprinting, CVE lookup for banners, a Tkinter or web GUI.

## Comparison with Nmap
| | PortScout | Nmap |
|---|---|---|
| Scan type | TCP connect | SYN, connect, UDP, and more |
| Service detection | Banner + port table | Probe database of more than 11,000 signatures |
| Dependencies | None | Npcap/libpcap |
| Purpose | Learning and quick audits | Professional tool |
