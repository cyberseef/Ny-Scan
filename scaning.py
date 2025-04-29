#!/usr/bin/env python3
"""
Ny-Scan: Host and Port Discovery Scanner using Nmap
Author: Cyberseef
Description: Professional Python script for host and port discovery using Nmap.
"""
import argparse
import subprocess
import sys
import logging
from typing import List, Optional
import re

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)

def parse_ports(ports: Optional[str]) -> str:
    """
    Parse and validate port input (single, comma-separated, or range).
    Returns a string suitable for nmap's -p argument.
    """
    if not ports:
        return "1-1024"  # Default port range
    # Validate ports: e.g., 22,80,443 or 1000-2000
    if re.match(r'^(\d+)(,\d+)*$', ports) or re.match(r'^(\d+)-(\d+)$', ports):
        return ports
    raise ValueError("Invalid port format. Use single, comma-separated, or range (e.g., 80,443,1000-2000)")

def run_scan(command: List[str]) -> None:
    """
    Run a scan command using subprocess and handle errors.
    """
    try:
        logging.info(f"Running: {' '.join(command)}")
        process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        print(process.stdout)
        if "Host seems down" in process.stdout:
            logging.warning("Host seems down, retrying with -Pn...")
            command.append("-Pn")
            process_retry = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            print(process_retry.stdout)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing command: {e.cmd}")
        print(e.output)

def host_scanning(target: str) -> None:
    """
    Perform various host discovery scans on the target.
    """
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
    for scan_name, command in scans.items():
        logging.info(f"Starting {scan_name}...")
        run_scan(command)
        logging.info(f"Completed {scan_name}\n")

def port_scanning(target: str, ports: str) -> None:
    """
    Perform various port discovery scans on the target.
    """
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
    for scan_name, command in scans.items():
        logging.info(f"Starting {scan_name}...")
        run_scan(command)
        logging.info(f"Completed {scan_name}\n")

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
    return mode, target, ports

def main() -> None:
    """
    Main entry point for the CLI.
    """
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
    args = parser.parse_args()

    # If no arguments provided, launch interactive menu
    if not (args.mode and args.target):
        mode, target, ports = interactive_menu()
    else:
        mode = args.mode
        target = args.target
        ports = args.ports

    if mode == "host":
        host_scanning(target)
    elif mode == "port":
        try:
            ports = parse_ports(ports)
        except ValueError as ve:
            logging.error(str(ve))
            sys.exit(1)
        port_scanning(target, ports)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()