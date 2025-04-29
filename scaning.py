#!/usr/bin/env python3
"""
Ny-Scan: Host and Port Discovery Scanner using Nmap
Author: [Your Name]
Description: Professional Python script for host and port discovery using Nmap.
"""
import argparse
import subprocess
import sys
import logging
from typing import List

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)

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


def port_scanning(target: str) -> None:
    """
    Perform various port discovery scans on the target.
    """
    scans = {
        "ICMP Ping Scan": ["nmap", "-sn", target, "-v"],
        "UDP Ping Scan": ["nmap", "-sU", "-p", "80", target, "-v"],
        "SYN Scan (Full Open Scan)": ["nmap", "-sS", target, "-v", "-T4"],
        "Stealth Scan (Half Open Scan)": ["nmap", "-sS", "--scanflags", "SYN", target, "-v", "-T4"],
        "FIN Scan": ["nmap", "-sF", target, "-v"],
        "Null Scan": ["nmap", "-sN", target, "-v"],
        "XMAS Scan": ["nmap", "-sX", target, "-v"],
        "Maimon Scan": ["nmap", "-sM", target, "-v"],
        "ACK Flag Scan": ["nmap", "-sA", target, "-v"],
        "TTL Based Scan": ["nmap", "--ttl", "128", "-sA", target, "-v"],
        "Window Scan": ["nmap", "-sW", target, "-v"]
    }
    for scan_name, command in scans.items():
        logging.info(f"Starting {scan_name}...")
        run_scan(command)
        logging.info(f"Completed {scan_name}\n")


def main() -> None:
    """
    Main entry point for the CLI.
    """
    parser = argparse.ArgumentParser(
        description="Ny-Scan: Host and Port Discovery Scanner using Nmap"
    )
    parser.add_argument(
        "mode",
        choices=["host", "port"],
        help="Choose 'host' for host discovery or 'port' for port discovery."
    )
    parser.add_argument(
        "target",
        help="Target IP address or hostname."
    )
    args = parser.parse_args()

    if args.mode == "host":
        host_scanning(args.target)
    elif args.mode == "port":
        port_scanning(args.target)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()