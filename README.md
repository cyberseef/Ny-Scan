# Ny-Scan

Ny-Scan is a professional Python tool for host and port discovery, leveraging the power of Nmap. It provides a convenient command-line interface for performing a variety of network reconnaissance scans, making it ideal for penetration testers, network administrators, and cybersecurity enthusiasts.

## Author
**Cyberseef**

## Features
- Host discovery using multiple Nmap techniques
- Port discovery with advanced scan types
- Easy-to-use command-line interface
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

### Host Discovery
Scan a single IP, subnet, or IP range:
```bash
sudo python3 scaning.py --mode host --target 192.168.1.1
sudo python3 scaning.py --mode host --target 192.168.1.0/24
sudo python3 scaning.py --mode host --target 192.168.1.10-192.168.1.20
```

### Port Discovery
Scan specific ports, a list, or a range (default: 1-1024):
```bash
sudo python3 scaning.py --mode port --target 192.168.1.10 --ports 22
sudo python3 scaning.py --mode port --target 192.168.1.10 --ports 22,80,443
sudo python3 scaning.py --mode port --target 192.168.1.10 --ports 1000-2000
sudo python3 scaning.py --mode port --target 192.168.1.10-192.168.1.20 --ports 80,443
```

#### Arguments
- `--mode`   : host or port (required)
- `--target` : IP address, IP range, subnet, or hostname (required)
- `--ports`  : (port scan only) single port, comma-separated list, or range (optional; default: 1-1024)

## Contributing
Contributions are welcome! Please open issues or submit pull requests for improvements.

## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
