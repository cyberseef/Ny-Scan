# Ny-Scan

Ny-Scan is a professional Python tool for host and port discovery, leveraging the power of Nmap. It provides a convenient command-line interface for performing a variety of network reconnaissance scans, making it ideal for penetration testers, network administrators, and cybersecurity enthusiasts.

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Interactive Menu vs. CLI](#interactive-menu-vs-cli)
- [Examples](#examples)
- [License](#license)
- [Contributing](#contributing)
- [Code of Conduct](#code-of-conduct)
- [Acknowledgements](#acknowledgements)

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
- See `requirements.txt` for details

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
3. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Ensure Nmap is installed:
   ```bash
   sudo apt update && sudo apt install nmap
   ```

## Usage
Run the script with root privileges for best results.

## Interactive Menu vs. CLI
- **Interactive Menu:**
  - If you run the script without any arguments, an interactive menu will guide you through selecting the scan mode, entering the target, and (for port scans) specifying ports.
  - Recommended for beginners or when you want a guided experience.
  - Example:
    ```bash
    sudo python3 scaning.py
    ```
- **Command-line Arguments (CLI):**
  - If you provide any of the CLI arguments (`--mode`, `--target`, etc.), the script will use those and skip the menu.
  - Recommended for advanced users, automation, or scripting.
  - Example:
    ```bash
    sudo python3 scaning.py --mode port --target 192.168.1.10 --ports 22,80,443
    ```

## Command-line Arguments
- `--mode` (required if not using menu): `host` for host discovery, `port` for port discovery
- `--target` (required if not using menu): Target IP address, range, subnet, or hostname (e.g., `192.168.1.1`, `192.168.1.0/24`, `192.168.1.1-10`)
- `--ports` (optional, port scan only): Ports to scan (single, comma-separated, or range, e.g., `80,443,1000-2000`). Default: `1-1024`

## Examples
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

## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Contributing
Contributions are welcome! Please open issues or submit pull requests for improvements. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Code of Conduct
Please note that this project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Acknowledgements
- [Nmap](https://nmap.org/)
- Python community
