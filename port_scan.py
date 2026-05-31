#!/usr/bin/env python3
"""
Simple TCP port scanner.
Usage: python port_scan.py target.example.com --ports 1-1024
"""
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

def parse_ports(s: str):
    parts = []
    for part in s.split(','):
        if '-' in part:
            a, b = part.split('-', 1)
            parts.extend(range(int(a), int(b) + 1))
        else:
            parts.append(int(part))
    return sorted(set(parts))

def scan_port(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, port)) == 0:
            return port
    except Exception:
        return None
    finally:
        s.close()
    return None

def main():
    p = argparse.ArgumentParser(description="Simple TCP port scanner")
    p.add_argument("target", help="IP or hostname to scan")
    p.add_argument("--ports", default="1-1024", help="Ports: single,comma-separated,or ranges e.g. 22,80,8000-8100")
    p.add_argument("--timeout", type=float, default=0.5, help="Socket timeout in seconds")
    p.add_argument("--workers", type=int, default=100, help="Max concurrent threads")
    args = p.parse_args()

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print("Could not resolve target:", args.target)
        return

    ports = parse_ports(args.ports)
    open_ports = []

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(scan_port, ip, port, args.timeout): port for port in ports}
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                open_ports.append(result)

    open_ports.sort()
    if open_ports:
        print(f"Open ports on {args.target} ({ip}):")
        for port in open_ports:
            print(f"  {port}")
    else:
        print(f"No open ports found on {args.target} ({ip}) in the scanned range.")

if __name__ == "__main__":
    main()
