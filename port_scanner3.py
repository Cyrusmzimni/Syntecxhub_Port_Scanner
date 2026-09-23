"""
TCP Port Scanner
-----------------
A simple, educational TCP connect-scan tool with concurrency, banner
grabbing, service name lookup, and JSON/CSV export.

For authorized/educational use only. Test against scanme.nmap.org or
your own systems/localhost.

Usage:
    python port_scanner.py <target> [-p PORTS] [-t TIMEOUT] [-w WORKERS]
                            [-b] [-o OUTPUT] [-v]

Examples:
    python port_scanner.py scanme.nmap.org
    python port_scanner.py scanme.nmap.org -p 1-1000 -b
    python port_scanner.py scanme.nmap.org -p 22,80,443 -o results.json
"""

import argparse
import csv
import json
import logging
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Port name mapping
# ---------------------------------------------------------------------------

COMMON_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}


def get_service_name(port):
    """Return the common service name for a port, or 'unknown' if unmapped."""
    return COMMON_PORTS.get(port, "unknown")


# ---------------------------------------------------------------------------
# Input parsing / resolution
# ---------------------------------------------------------------------------

def parse_ports(port_input):
    """
    Convert a user-supplied port string into a sorted list of unique ports.

    Accepts single ports, comma-separated lists, and dash ranges, e.g.:
        "80"            -> [80]
        "22,80,443"     -> [22, 80, 443]
        "1-100"         -> [1, 2, ..., 100]
        "20-22,80,443"  -> [20, 21, 22, 80, 443]

    Raises:
        ValueError: if the input contains a non-numeric or malformed entry.
    """
    ports = set()
    parts = port_input.split(",")

    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_str, end_str = part.split("-")
            start = int(start_str)
            end = int(end_str)
            if start > end:
                raise ValueError(f"Invalid range: {part} (start > end)")
            for p in range(start, end + 1):
                ports.add(p)
        else:
            ports.add(int(part))

    if not ports:
        raise ValueError("No ports provided")

    return sorted(ports)


def resolve_target(target):
    """
    Resolve a hostname or IP string to an IP address.

    Raises:
        ValueError: if the hostname cannot be resolved.
    """
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve hostname: {target}") from exc


# ---------------------------------------------------------------------------
# Core scanning logic
# ---------------------------------------------------------------------------

def scan_port(target_ip, port, timeout=1):
    """
    Attempt a TCP connection to a single port.

    Returns:
        tuple: (port, status) where status is "open" or "closed/filtered".
    """
    logger.debug("Scanning %s:%s", target_ip, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target_ip, port))
    finally:
        sock.close()

    status = "open" if result == 0 else "closed/filtered"
    logger.debug("Result for %s:%s -> %s", target_ip, port, status)
    return port, status


def scan_targets(target_ip, ports_to_scan, max_workers=100, on_progress=None):
    """
    Scan multiple ports concurrently using a thread pool.

    Args:
        on_progress (callable, optional): called as on_progress(done, total)
            after each port finishes, for live progress reporting.

    Returns:
        list[tuple]: (port, status) for every port scanned, sorted by port.
    """
    results = []
    total = len(ports_to_scan)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(scan_port, target_ip, port)
            for port in ports_to_scan
        ]

        for completed_count, future in enumerate(as_completed(futures), start=1):
            results.append(future.result())
            if on_progress:
                on_progress(completed_count, total)

    return sorted(results, key=lambda item: item[0])


# ---------------------------------------------------------------------------
# Banner grabbing
# ---------------------------------------------------------------------------

def grab_banner(target_ip, port, timeout=1):
    """
    Attempt to read a service banner from an already-open port.

    Returns:
        str: the banner text (trimmed), or None if nothing was received
             or the connection/read failed.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))
        data = sock.recv(1024)
        sock.close()
        banner = data.decode(errors="ignore").strip()
        return banner if banner else None
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        logger.debug("Banner grab failed for %s:%s (%s)", target_ip, port, exc)
        return None


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_json(results, filepath):
    """Write results (list of dicts) to a JSON file."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)


def export_csv(results, filepath):
    """Write results (list of dicts) to a CSV file."""
    fieldnames = ["port", "status", "service", "banner"]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow(row)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="port_scanner",
        description="A simple TCP connect port scanner for educational/authorized use.",
    )
    parser.add_argument("target", help="Target IP address or hostname (e.g. scanme.nmap.org)")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Port(s) to scan: single (80), list (22,80,443), or range (1-1000). Default: 1-1024",
    )
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Per-port timeout in seconds. Default: 1.0")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Max concurrent threads. Default: 100")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show debug-level logging output.")
    parser.add_argument(
        "-b", "--banner", action="store_true",
        help="Attempt to grab a service banner from each open port.",
    )
    parser.add_argument(
        "-o", "--output",
        help="Path to write results to (format inferred from extension: .json or .csv)",
    )
    return parser


def configure_logging(verbose):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def print_progress(done, total):
    """Overwrite a single terminal line to show live scan progress."""
    percent = (done / total) * 100
    sys.stdout.write(f"\rScanning... {done}/{total} ports ({percent:.0f}%)")
    sys.stdout.flush()
    if done == total:
        sys.stdout.write("\n")


def main():
    parser = build_parser()
    args = parser.parse_args()

    configure_logging(args.verbose)

    try:
        ports_to_scan = parse_ports(args.ports)
    except ValueError as exc:
        logger.error("Invalid port input: %s", exc)
        raise SystemExit(1)

    try:
        target_ip = resolve_target(args.target)
    except ValueError as exc:
        logger.error(str(exc))
        raise SystemExit(1)

    logger.info("Scanning %s (%s) - %d port(s)", args.target, target_ip, len(ports_to_scan))
    start_time = datetime.now()

    progress_callback = print_progress if not args.verbose else None
    raw_results = scan_targets(
        target_ip,
        ports_to_scan,
        max_workers=args.workers,
        on_progress=progress_callback,
    )

    # Enrich open ports with service name + optional banner
    enriched_results = []
    for port, status in raw_results:
        entry = {
            "port": port,
            "status": status,
            "service": get_service_name(port) if status == "open" else None,
            "banner": None,
        }
        if status == "open" and args.banner:
            entry["banner"] = grab_banner(target_ip, port, timeout=args.timeout)
        enriched_results.append(entry)

    open_results = [r for r in enriched_results if r["status"] == "open"]

    for r in open_results:
        line = f"Port {r['port']} ({r['service']}): open"
        if r["banner"]:
            line += f" - banner: {r['banner']!r}"
        logger.info(line)

    elapsed = datetime.now() - start_time
    logger.info("Scan completed in %s", elapsed)
    logger.info("Open ports found: %s", [r["port"] for r in open_results] or "none")

    if args.output:
        if args.output.endswith(".json"):
            export_json(enriched_results, args.output)
        elif args.output.endswith(".csv"):
            export_csv(enriched_results, args.output)
        else:
            logger.error("Unsupported output format. Use a .json or .csv filename.")
            raise SystemExit(1)
        logger.info("Results written to %s", args.output)


if __name__ == "__main__":
    main()