import subprocess
import sys

def run_scan(command):
    try:
        process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        print(process.stdout)

        if "Host seems down" in process.stdout:
            print("Host seems down, retrying with -Pn...")
            command.append("-Pn")  # Add -Pn to the command list
            process_retry = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            print(process_retry.stdout)

    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e.cmd}")
        print(e.output)

def host_scanning(target):
    scans = {
        "ARP Ping Scan": ["nmap", "-PR", target],
        "ICMP Echo Ping": ["nmap", "-PE", target],
        "ICMP Echo Ping Sweep": ["nmap", "-sn", "-PE", target],
        "ICMP Timestamp Ping": ["nmap", "-PP", target],
        "ICMP Address Mask Ping": ["nmap", "-PM", target],
        "UDP Ping Scan": ["nmap", "-sU", "-p", "80", target],  # Example: Scanning port 80
        "TCP SYN Scan": ["nmap", "-sS", target],
        "TCP ACK Scan": ["nmap", "-sA", target],
        "TCP Null Scan": ["nmap", "-sN", target],
        "TCP XMAS Scan": ["nmap", "-sX", target],
        "TCP FIN Scan": ["nmap", "-sF", target],
        "IP Protocol Scan": ["nmap", "-sO", "-p", "1,6,17", target]  # ICMP, TCP, UDP
    }

    for scan_name, command in scans.items():
        print(f"Starting {scan_name}...")
        run_scan(command)
        print(f"Completed {scan_name}\n")

def port_scanning(target):
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
        print(f"Starting {scan_name}...")
        run_scan(command)
        print(f"Completed {scan_name}\n")

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 script.py <port> <target>")
        sys.exit(1)

    mode = sys.argv[1].lower()
    target_ip = sys.argv[2]

    if mode == "port":
        port_scanning(target_ip)
    else:
        print("Invalid mode selected. Use 'port' for port scanning.")
        sys.exit(1)

if __name__ == "__main__":
    main()