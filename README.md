# Ny-Scan

Ny-Scan is a professional Python tool for host and port discovery, leveraging the power of Nmap. It provides a convenient command-line interface and a modern GUI for performing a variety of network reconnaissance scans, making it ideal for penetration testers, network administrators, and cybersecurity enthusiasts.

## Project Structure
```
Ny-Scan/
├── src/
│   ├── gui.py         # Graphical User Interface (GUI)
│   ├── scanner.py     # Core scanning logic
│   └── scaning.py     # Command-Line Interface (CLI)
├── requirements.txt
├── README.md
├── LICENSE
└── ...
```

## Where to Find the CLI and GUI
- The **command-line interface (CLI)** is in: `src/scaning.py`
- The **graphical user interface (GUI)** is in: `src/gui.py`

## Features
- Host discovery using multiple Nmap techniques
- Port discovery with advanced scan types
- Easy-to-use command-line interface
- Modern graphical user interface (GUI)
- Informative logging and error handling
- Designed for Linux environments (Kali/Parrot preferred)

## Requirements
- Python 3.7+
- [Nmap](https://nmap.org/) must be installed and available in your system PATH
- See `requirements.txt` for details

## Installation
1. Clone this repository:
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
5. (Optional, for GUI) Install Tkinter if not already available:
   ```bash
   sudo apt install python3-tk
   ```

## Usage
Run the script with root privileges for best results.

### CLI Usage
- Run the CLI:
  ```bash
  sudo python3 src/scaning.py
  ```
  or with arguments:
  ```bash
  sudo python3 src/scaning.py --mode port --target 192.168.1.10 --ports 22,80,443
  ```

### GUI Usage
- Run the GUI (requires Tkinter):
  ```bash
  sudo python3 src/gui.py
  ```
- The GUI provides fields for scan mode, target, and ports, and displays results in a user-friendly window.

## Interactive Menu vs. CLI vs. GUI
- **Interactive Menu:**
  - If you run the CLI script without any arguments, an interactive menu will guide you through selecting the scan mode, entering the target, and (for port scans) specifying ports.
- **Command-line Arguments (CLI):**
  - Provide CLI arguments (`--mode`, `--target`, etc.) to skip the menu.
- **Graphical User Interface (GUI):**
  - Use the GUI for a point-and-click experience. All scanning logic is shared with the CLI for consistency.

## Command-line Arguments
- `--mode` (required if not using menu): `host` for host discovery, `port` for port discovery
- `--target` (required if not using menu): Target IP address, range, subnet, or hostname (e.g., `192.168.1.1`, `192.168.1.0/24`, `192.168.1.1-10`)
- `--ports` (optional, port scan only): Ports to scan (single, comma-separated, or range, e.g., `80,443,1000-2000`). Default: `1-1024`

## Examples
- Host Discovery (on a subnet):
  ```bash
  sudo python3 src/scaning.py --mode host --target 192.168.1.0/24
  ```
- Port Discovery (on a single IP and specific ports):
  ```bash
  sudo python3 src/scaning.py --mode port --target 192.168.1.10 --ports 22,80,443
  ```
- Port Discovery (on a range of IPs and port range):
  ```bash
  sudo python3 src/scaning.py --mode port --target 192.168.1.10-192.168.1.20 --ports 1000-2000
  ```
- Port Discovery (default ports 1-1024):
  ```bash
  sudo python3 src/scaning.py --mode port --target 192.168.1.10
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
