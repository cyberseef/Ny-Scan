import argparse
import subprocess
import sys
import logging
from typing import List, Optional, Tuple, Dict
import re

def parse_ports(ports: Optional[str]) -> str:
    if not ports:
        return "1-1024"
    if re.match(r'^(\d+)(,\d+)*$', ports) or re.match(r'^(\d+)-(\d+)$', ports):
        return ports
    raise ValueError("Invalid port format. Use single, comma-separated, or range (e.g., 80,443,1000-2000)")

def run_scan(command: List[str]) -> str:
    try:
        logging.info(f"Running: {' '.join(command)}")
        process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        output = process.stdout
        if "Host seems down" in output:
            logging.warning("Host seems down, retrying with -Pn...")
            command.append("-Pn")
            process_retry = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            output += process_retry.stdout
        return output
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing command: {e.cmd}")
        return e.output

def parse_nmap_hosts(output: str) -> List[str]:
    # Extract up hosts from nmap output
    hosts = set()
    for line in output.splitlines():
        if re.search(r'Host is up', line):
            # Find previous line with IP/hostname
            idx = output.splitlines().index(line)
            if idx > 0:
                prev = output.splitlines()[idx-1]
                m = re.search(r'Nmap scan report for (.+)', prev)
                if m:
                    hosts.add(m.group(1))
    return sorted(hosts)

def parse_nmap_ports_all_statuses(output: str) -> Dict[str, List[Tuple[int, str, str]]]:
    # Returns {host: [(port, proto, status), ...]}
    results = {}
    current_host = None
    in_ports_section = False
    for line in output.splitlines():
        m = re.match(r'Nmap scan report for (.+)', line)
        if m:
            current_host = m.group(1)
            results.setdefault(current_host, [])
            in_ports_section = False
        if line.strip().startswith('PORT'):
            in_ports_section = True
            continue
        if in_ports_section and line.strip() == '':
            in_ports_section = False
        if in_ports_section and current_host:
            port_match = re.match(r'^(\d+)/(tcp|udp)\s+(\w+)', line)
            if port_match:
                port = int(port_match.group(1))
                proto = port_match.group(2)
                status = port_match.group(3)
                results[current_host].append((port, proto, status))
    return results

def host_scanning(target: str) -> Dict[str, str]:
    scans = {
        "ARP Ping Scan": ["nmap", "-PR", target],
        "ICMP Echo Ping": ["nmap", "-PE", target],
        "ICMP Echo Ping Sweep": ["nmap", "-sn", "-PE", target],
        "ICMP Timestamp Ping": ["nmap", "-PP", target],
        "ICMP Address Mask Ping": ["nmap", "-PM", target],
        "UDP Ping Scan": ["nmap", "-sU", "-p", "80", target],
        "TCP SYN Scan": ["nmap", "-sS", target],
        "TCP ACK Scan": ["nmap", "-sA", target],
        "TCP Null Scan": ["nmap", "-sN", target],
        "TCP XMAS Scan": ["nmap", "-sX", target],
        "TCP FIN Scan": ["nmap", "-sF", target],
        "IP Protocol Scan": ["nmap", "-sO", "-p", "1,6,17", target]
    }
    detailed = {}
    all_hosts = set()
    for scan_name, command in scans.items():
        logging.info(f"Starting {scan_name}...")
        output = run_scan(command)
        detailed[scan_name] = output
        hosts = parse_nmap_hosts(output)
        all_hosts.update(hosts)
        logging.info(f"Completed {scan_name}\n")
    summary = "Discovered hosts (sorted, unique):\n" + "\n".join(sorted(all_hosts))
    return {"summary": summary, "detailed": detailed}

def port_scanning(target: str, ports: str) -> Dict[str, str]:
    scans = {
        "ICMP Ping Scan": ["nmap", "-sn", target, "-v"],
        "UDP Ping Scan": ["nmap", "-sU", "-p", ports, target, "-v"],
        "SYN Scan (Full Open Scan)": ["nmap", "-sS", "-p", ports, target, "-v", "-T4"],
        "Stealth Scan (Half Open Scan)": ["nmap", "-sS", "--scanflags", "SYN", "-p", ports, target, "-v", "-T4"],
        "FIN Scan": ["nmap", "-sF", "-p", ports, target, "-v"],
        "Null Scan": ["nmap", "-sN", "-p", ports, target, "-v"],
        "XMAS Scan": ["nmap", "-sX", "-p", ports, target, "-v"],
        "Maimon Scan": ["nmap", "-sM", "-p", ports, target, "-v"],
        "ACK Flag Scan": ["nmap", "-sA", "-p", ports, target, "-v"],
        "TTL Based Scan": ["nmap", "--ttl", "128", "-sA", "-p", ports, target, "-v"],
        "Window Scan": ["nmap", "-sW", "-p", ports, target, "-v"]
    }
    detailed = {}
    all_ports_status = {}
    for scan_name, command in scans.items():
        logging.info(f"Starting {scan_name}...")
        output = run_scan(command)
        detailed[scan_name] = output
        scan_ports = parse_nmap_ports_all_statuses(output)
        for host, portlist in scan_ports.items():
            if host not in all_ports_status:
                all_ports_status[host] = []
            all_ports_status[host].extend(portlist)
        logging.info(f"Completed {scan_name}\n")
    # Remove duplicates and sort
    for host in all_ports_status:
        all_ports_status[host] = sorted(set(all_ports_status[host]), key=lambda x: (x[0], x[1]))
    # Build summary table
    summary_lines = []
    for host in sorted(all_ports_status.keys()):
        summary_lines.append(f"\nHost: {host}")
        summary_lines.append(f"{'Port':>6} {'Proto':>6} {'Status':>10}")
        summary_lines.append('-'*26)
        for port, proto, status in all_ports_status[host]:
            summary_lines.append(f"{port:>6} {proto:>6} {status:>10}")
    summary = "Port scan results (all statuses):\n" + ("\n".join(summary_lines) if summary_lines else "No ports found.")
    return {"summary": summary, "detailed": detailed}

def interactive_menu():
    print("\n=== Ny-Scan Interactive Menu ===")
    print("1. Host Discovery Scan")
    print("2. Port Discovery Scan")
    while True:
        mode_choice = input("Select scan mode (1 for Host, 2 for Port): ").strip()
        if mode_choice in ("1", "2"):
            break
        print("Invalid choice. Please enter 1 or 2.")
    mode = "host" if mode_choice == "1" else "port"
    target = input("Enter target IP, range, subnet, or hostname: ").strip()
    ports = None
    if mode == "port":
        ports = input("Enter ports (single, comma-separated, or range, e.g., 80,443,1000-2000) [default: 1-1024]: ").strip()
        if not ports:
            ports = "1-1024"
    detail = input("Show detailed output? (y/N): ").strip().lower() == 'y'
    return mode, target, ports, detail

def cli_main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format='[%(levelname)s] %(message)s'
    )
    parser = argparse.ArgumentParser(
        description="Ny-Scan: Host and Port Discovery Scanner using Nmap"
    )
    parser.add_argument(
        "--mode",
        required=False,
        choices=["host", "port"],
        help="Choose 'host' for host discovery or 'port' for port discovery."
    )
    parser.add_argument(
        "--target",
        required=False,
        help="Target IP address, range, subnet, or hostname. E.g., 192.168.1.1, 192.168.1.0/24, 192.168.1.1-10"
    )
    parser.add_argument(
        "--ports",
        required=False,
        help="(Port scan only) Ports to scan: single, comma-separated, or range (e.g., 80,443,1000-2000). Default: 1-1024"
    )
    parser.add_argument(
        "--detailed",
        action='store_true',
        help="Show detailed output for each scan type."
    )
    args = parser.parse_args()

    if not (args.mode and args.target):
        mode, target, ports, detail = interactive_menu()
    else:
        mode = args.mode
        target = args.target
        ports = args.ports
        detail = args.detailed

    if mode == "host":
        result = host_scanning(target)
    elif mode == "port":
        try:
            ports = parse_ports(ports)
        except ValueError as ve:
            logging.error(str(ve))
            sys.exit(1)
        result = port_scanning(target, ports)
    else:
        parser.print_help()
        sys.exit(1)

    print(result["summary"])
    if detail:
        print("\n--- Detailed Output ---")
        for scan_name, output in result["detailed"].items():
            print(f"\n=== {scan_name} ===\n{output}")

    if mode == 'host':
        scan_names = [
            "ARP Ping Scan", "ICMP Echo Ping", "ICMP Echo Ping Sweep", "ICMP Timestamp Ping",
            "ICMP Address Mask Ping", "UDP Ping Scan", "TCP SYN Scan", "TCP ACK Scan",
            "TCP Null Scan", "TCP XMAS Scan", "TCP FIN Scan", "IP Protocol Scan"
        ]
    else:
        scan_names = [
            "ICMP Ping Scan", "UDP Ping Scan", "SYN Scan (Full Open Scan)", "Stealth Scan (Half Open Scan)",
            "FIN Scan", "Null Scan", "XMAS Scan", "Maimon Scan", "ACK Flag Scan",
            "TTL Based Scan", "Window Scan"
        ]

    # Implement progress bar logic here
    # This is a placeholder and should be replaced with actual implementation
    print("\n--- Progress Bar ---")
    for scan_name in scan_names:
        print(f"Starting {scan_name}...")
        # Simulate progress
        import time
        time.sleep(1)  # Simulating work done
        print(f"{scan_name} completed.")

    print("\n--- Scan Completed ---") 