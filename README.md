# Ny-Scan

Ny-Scan is a professional Python tool for host and port discovery, leveraging the power of Nmap. It provides a convenient command-line interface for performing a variety of network reconnaissance scans, making it ideal for penetration testers, network administrators, and cybersecurity enthusiasts.

## Author
**Cyberseef**

## Features
- Host discovery using multiple Nmap techniques
- Port discovery with advanced scan types
- Easy-to-use command-line interface
- Interactive menu for beginners
- Informative logging and error handling
- Designed for Linux environments (Kali/Parrot preferred)

## Requirements
- Python 3.7+
- [Nmap](https://nmap.org/) must be installed and available in your system PATH

## Installation
1. Clone this repository or download `scaning.py`:
   ```bash
   git clone https://github.com/yourusername/Ny-Scan.git
   cd Ny-Scan
   ```
2. (Optional) Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install Python dependencies (if any):
   ```bash
   pip install -r requirements.txt
   ```
4. Ensure Nmap is installed:
   ```bash
   sudo apt update && sudo apt install nmap
   ```

## Usage
Run the script with root privileges for best results.

### Interactive Menu (Recommended for Beginners)
If you run the script without any arguments, an interactive menu will guide you through selecting the scan mode, entering the target, and (for port scans) specifying ports:

```bash
sudo python3 scaning.py
```

You will be prompted to:
- Select scan mode (host or port discovery)
- Enter the target (IP, range, subnet, or hostname)
- (For port scan) Enter ports (single, comma-separated, or range; default: 1-1024)

### Command-line Arguments (Advanced/Scriptable)
- `--mode` (required if not using menu): `host` for host discovery, `port` for port discovery
- `--target` (required if not using menu): Target IP address, range, subnet, or hostname (e.g., `192.168.1.1`, `192.168.1.0/24`, `192.168.1.1-10`)
- `--ports` (optional, port scan only): Ports to scan (single, comma-separated, or range, e.g., `80,443,1000-2000`). Default: `1-1024`

#### Examples
- Host Discovery (on a subnet):
  ```bash
  sudo python3 scaning.py --mode host --target 192.168.1.0/24
  ```
- Port Discovery (on a single IP and specific ports):
  ```bash
  sudo python3 scaning.py --mode port --target 192.168.1.10 --ports 22,80,443
  ```
- Port Discovery (on a range of IPs and port range):
  ```bash
  sudo python3 scaning.py --mode port --target 192.168.1.10-192.168.1.20 --ports 1000-2000
  ```
- Port Discovery (default ports 1-1024):
  ```bash
  sudo python3 scaning.py --mode port --target 192.168.1.10
  ```

## Contributing
Contributions are welcome! Please open issues or submit pull requests for improvements.

## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
