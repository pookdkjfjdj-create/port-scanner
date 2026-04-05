#!/usr/bin/env python3
"""port-scanner -- fast TCP port scanner with service detection."""

from __future__ import annotations

import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── Common ports ────────────────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}


def _scan_port(host: str, port: int, timeout: float = 1.0) -> tuple[int, bool, str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        service = COMMON_PORTS.get(port, "")
        if result == 0 and not service:
            try:
                s.settimeout(0.5)
                s.send(b"\n")
                banner = s.recv(64).decode(errors="ignore").strip()[:40]
                if banner:
                    service = banner
            except Exception:
                pass
        s.close()
        return port, result == 0, service
    except Exception:
        return port, False, ""


def scan(
    host: str,
    ports: list[int] | None = None,
    *,
    range_start: int = 1,
    range_end: int = 1024,
    timeout: float = 0.5,
    threads: int = 100,
) -> list[tuple[int, bool, str]]:
    """Scan a host for open ports."""
    if ports is None:
        ports = list(range(range_start, range_end + 1))

    results: list[tuple[int, bool, str]] = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(_scan_port, host, p, timeout): p for p in ports}
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception:
                pass
    return sorted(results)


def format_results(results: list[tuple[int, bool, str]], host: str) -> str:
    open_ports = [(p, s) for p, ok, s in results if ok]
    lines = [f"Scan results for {host}", f"{'PORT':<8} {'SERVICE':<20}", f"{'─':─<8} {'─':─<20}"]
    if not open_ports:
        lines.append("  No open ports found")
    else:
        for port, svc in open_ports:
            svc_display = svc or "unknown"
            lines.append(f"  {port:<8} {svc_display:<20}")
    lines.append(f"\n{len(open_ports)} open port(s)")
    return "\n".join(lines)


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ('--help', '-h'):
        print('Usage:')
        print('  python -m port_scanner <host>')
        print('  python -m port_scanner <host> --range 1-65535')
        print('  python -m port_scanner <host> --ports 22,80,443,3306')
        print('  python -m port_scanner <host> --top')
        return

    host = sys.argv[1]
    ports: list[int] | None = None
    start, end = 1, 1024

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == '--ports':
            i += 1
            ports = [int(p) for p in sys.argv[i].split(',')]
        elif arg == '--range':
            i += 1
            parts = sys.argv[i].split('-')
            start, end = int(parts[0]), int(parts[1])
        elif arg == '--top':
            ports = list(COMMON_PORTS.keys())
        i += 1

    print(f"Scanning {host}...")
    t0 = time.time()
    results = scan(host, ports, range_start=start, range_end=end)
    elapsed = time.time() - t0
    print(format_results(results, host))
    print(f"Scan took {elapsed:.1f}s")


if __name__ == '__main__':
    main()
