import socket
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_ports(target_ip, port, timeout=1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((target_ip, port))
    sock.close()

    if result == 0:
        return port, "open"
    else:
        return port, "closed/filtered"
    
def parse_ports(port_input):
    ports = set()
    parts = port_input.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            start_str, end_str = part.split('-')
            start = int(start_str)
            end = int(end_str)
            for p in range(start, end + 1):
                ports.add(p)
        else:
            ports.add(int(part))
    return sorted(ports)

def scan_targets(target_ip, ports_to_scan, max_workers=100):
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_ports, target_ip, port) for port in ports_to_scan]
        
        for future in as_completed(futures):
            port, status = future.result()
            if status == "open":
                print(f"Port {port}: {status}") 
                open_ports.append(port)
    return sorted(open_ports)

        

def main():
    target = input("Enter target IP or hostname (e.g. scanme.nmap.org): ").strip()
    port_input = input("Enter port(s) to scan (e.g. 80 or 1-1000 or 22,80,443): ").strip()
 
    try:
        ports_to_scan = parse_ports(port_input)
    except ValueError:
        print(f"Invalid port input: {port_input}")
        sys.exit(1)
 
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Could not resolve hostname: {target}")
        sys.exit(1)
 
    print(f"Scanning {target} ({target_ip}) — {len(ports_to_scan)} port(s)...")
    start_time = datetime.now()
 
    open_ports = scan_targets(target_ip, ports_to_scan)
 
    end_time = datetime.now()
 
    print(f"\nScan completed in {end_time - start_time}")
    print(f"Open ports found: {open_ports if open_ports else 'none'}")
 
 
if __name__ == "__main__":
    main()
 