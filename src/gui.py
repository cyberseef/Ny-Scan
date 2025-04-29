import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
from scanner import host_scanning, port_scanning, parse_ports, run_scan, parse_nmap_ports_all_statuses
import time

# Modern color scheme
BG_COLOR = '#181c24'         # Deep blue-gray
CARD_BG = '#262b34'          # Lighter for cards (increased contrast)
FG_COLOR = '#e0e6ed'         # Light gray
ACCENT = '#00ffe7'           # Brighter teal accent
HEADER_ACCENT = '#1de9b6'    # Lighter teal for header
BTN_COLOR = '#00bfae'        # Button background
BTN_TEXT = '#181c24'         # Button text (dark for contrast)
TAB_BG = '#23272f'           # Tab background
OUTPUT_FG = '#e0e6ed'        # Output text color (visible on dark)

class NyScanGUI:
    def __init__(self, root):
        self.root = root
        self.root.title('Ny-Scan GUI')
        self.root.geometry('1200x1000')
        self.root.configure(bg=BG_COLOR)
        self.root.resizable(False, False)
        self.setup_style()
        self.build_gui()

    def setup_style(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background=BG_COLOR)
        style.configure('Card.TFrame', background=CARD_BG, relief='flat')
        style.configure('TLabel', background=BG_COLOR, foreground=FG_COLOR, font=('Segoe UI', 13))
        style.configure('Header.TLabel', font=('Segoe UI', 28, 'bold'), foreground=HEADER_ACCENT, background=BG_COLOR)
        style.configure('SubHeader.TLabel', font=('Segoe UI', 15, 'italic'), foreground=ACCENT, background=BG_COLOR)
        style.configure('Section.TLabel', font=('Segoe UI', 17, 'bold'), foreground=ACCENT, background=CARD_BG)
        style.configure('CardLabel.TLabel', background=CARD_BG, foreground=FG_COLOR, font=('Segoe UI', 13))
        style.configure('TButton', background=BTN_COLOR, foreground=BTN_TEXT, font=('Segoe UI', 14, 'bold'), borderwidth=0, focusthickness=3, focuscolor=ACCENT, padding=10)
        style.map('TButton', background=[('active', HEADER_ACCENT)])
        style.configure('TCheckbutton', background=CARD_BG, foreground=FG_COLOR, font=('Segoe UI', 12))
        style.configure('TCombobox', fieldbackground='white', background='white', foreground='black', font=('Segoe UI', 13))
        style.configure('Accent.Horizontal.TProgressbar', troughcolor=CARD_BG, bordercolor=CARD_BG, background=ACCENT, lightcolor=ACCENT, darkcolor=ACCENT, thickness=16)
        style.configure('TNotebook', background=CARD_BG, tabposition='n')
        style.configure('TNotebook.Tab', font=('Segoe UI', 13, 'bold'), padding=[16, 8], background=CARD_BG, foreground=ACCENT)
        style.map('TNotebook.Tab', background=[('selected', BG_COLOR)], foreground=[('selected', HEADER_ACCENT)])

    def build_gui(self):
        frm = ttk.Frame(self.root, padding=0)
        frm.pack(fill=tk.BOTH, expand=True)

        # Header
        header_frame = ttk.Frame(frm, style='TFrame')
        header_frame.pack(fill=tk.X, pady=(24, 0))
        logo = tk.Label(header_frame, text='🛰️', font=('Segoe UI Emoji', 48), bg=BG_COLOR)
        logo.pack(side=tk.TOP, pady=(0, 8))
        title = ttk.Label(header_frame, text='Ny-Scan Network Scanner', style='Header.TLabel', anchor='center', justify='center')
        title.pack(side=tk.TOP, pady=(0, 4))
        subtitle = ttk.Label(header_frame, text='Professional Nmap-based host and port discovery tool', style='SubHeader.TLabel', anchor='center', justify='center')
        subtitle.pack(side=tk.TOP, pady=(0, 12))
        divider = tk.Frame(frm, bg=ACCENT, height=2)
        divider.pack(fill=tk.X, padx=120, pady=(0, 24))

        # Scan Options Card
        options_card = ttk.Frame(frm, style='Card.TFrame', padding=32)
        options_card.pack(fill=tk.X, padx=80, pady=(0, 32))
        # Section header
        ttk.Label(options_card, text='Scan Options', style='Section.TLabel').pack(anchor=tk.W, pady=(0, 18))
        # Inputs
        input_frame = ttk.Frame(options_card, style='Card.TFrame')
        input_frame.pack(anchor=tk.CENTER, pady=(0, 0))
        # Scan Mode
        ttk.Label(input_frame, text='Scan Mode:', style='CardLabel.TLabel').grid(row=0, column=0, sticky=tk.W, pady=10, padx=(0, 12))
        self.mode_var = tk.StringVar(value='host')
        mode_combo = ttk.Combobox(input_frame, textvariable=self.mode_var, values=['host', 'port'], state='readonly', width=18)
        mode_combo.grid(row=0, column=1, sticky=tk.W, pady=10, padx=(0, 0))
        # Target
        ttk.Label(input_frame, text='Target:', style='CardLabel.TLabel').grid(row=1, column=0, sticky=tk.W, pady=10, padx=(0, 12))
        self.target_entry = tk.Entry(input_frame, width=48, font=('Segoe UI', 13), bg='white', fg='black', insertbackground='black', relief='flat', highlightthickness=1, highlightbackground=ACCENT)
        self.target_entry.grid(row=1, column=1, sticky=tk.W, pady=10, padx=(0, 0))
        self.target_entry.insert(0, '')
        # Ports
        ttk.Label(input_frame, text='Ports (for port scan):', style='CardLabel.TLabel').grid(row=2, column=0, sticky=tk.W, pady=10, padx=(0, 12))
        self.ports_entry = tk.Entry(input_frame, width=48, font=('Segoe UI', 13), bg='white', fg='black', insertbackground='black', relief='flat', highlightthickness=1, highlightbackground=ACCENT)
        self.ports_entry.grid(row=2, column=1, sticky=tk.W, pady=10, padx=(0, 0))
        self.ports_entry.insert(0, '1-1024')
        # Start Scan button
        self.scan_btn = ttk.Button(options_card, text='Start Scan', command=self.on_scan)
        self.scan_btn.pack(pady=(24, 0))
        # Progress bar (long, themed, only visible during scan)
        self.progress = ttk.Progressbar(options_card, mode='determinate', length=700, style='Accent.Horizontal.TProgressbar')
        self.progress.pack(fill=tk.X, pady=(24, 0))
        self.progress['value'] = 0
        self.progress.pack_forget()  # Hide initially

        # Output Card
        output_card = ttk.Frame(frm, style='Card.TFrame', padding=48)
        output_card.pack(fill=tk.BOTH, expand=True, padx=100, pady=(0, 32))
        ttk.Label(output_card, text='Scan Output', style='Section.TLabel').pack(anchor=tk.W, pady=(0, 4))
        # Tabs for summary/detailed
        self.tabs = ttk.Notebook(output_card)
        self.summary_tab = ttk.Frame(self.tabs, style='Card.TFrame')
        self.detailed_tab = ttk.Frame(self.tabs, style='Card.TFrame')
        self.tabs.add(self.summary_tab, text='Summary')
        self.tabs.add(self.detailed_tab, text='Detailed')
        self.tabs.pack(fill=tk.BOTH, expand=True, padx=2, pady=(0,2))
        # Output text widgets (dynamic height)
        self.summary_text = scrolledtext.ScrolledText(self.summary_tab, width=100, font=('Consolas', 12), bg=CARD_BG, fg=OUTPUT_FG, insertbackground=OUTPUT_FG, borderwidth=0, highlightthickness=0, padx=12, pady=12, relief='flat')
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        self.detailed_text = scrolledtext.ScrolledText(self.detailed_tab, width=100, font=('Consolas', 12), bg=CARD_BG, fg=OUTPUT_FG, insertbackground=OUTPUT_FG, borderwidth=0, highlightthickness=0, padx=12, pady=12, relief='flat')
        self.detailed_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        # Copy/Save buttons
        btn_frame = ttk.Frame(output_card, style='Card.TFrame')
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(btn_frame, text='Copy Output', command=self.copy_output).pack(side=tk.LEFT, padx=8)
        ttk.Button(btn_frame, text='Save Output', command=self.save_output).pack(side=tk.LEFT, padx=8)
        # Footer
        footer = ttk.Label(frm, text='© 2024 Cyberseef | Powered by Nmap', font=('Segoe UI', 11, 'italic'), foreground=ACCENT, background=BG_COLOR)
        footer.pack(side=tk.BOTTOM, pady=(16, 0))

    def on_scan(self):
        mode = self.mode_var.get()
        target = self.target_entry.get().strip()
        ports = self.ports_entry.get().strip()
        if not target:
            messagebox.showerror('Input Error', 'Target is required.')
            return
        self.scan_btn.config(state=tk.DISABLED)
        self.progress['value'] = 0
        self.progress.pack(fill=tk.X, pady=(24, 0))  # Show progress bar
        self.summary_text.config(state=tk.NORMAL)
        self.detailed_text.config(state=tk.NORMAL)
        self.summary_text.delete(1.0, tk.END)
        self.detailed_text.delete(1.0, tk.END)
        threading.Thread(target=self.run_scan_with_progress, args=(mode, target, ports)).start()

    def run_scan_with_progress(self, mode, target, ports):
        if mode == 'host':
            scan_names = [
                "ARP Ping Scan", "ICMP Echo Ping", "ICMP Echo Ping Sweep", "ICMP Timestamp Ping",
                "ICMP Address Mask Ping", "UDP Ping Scan", "TCP SYN Scan", "TCP ACK Scan",
                "TCP Null Scan", "TCP XMAS Scan", "TCP FIN Scan", "IP Protocol Scan"
            ]
            scan_dict = {
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
        else:
            scan_names = [
                "ICMP Ping Scan", "UDP Ping Scan", "SYN Scan (Full Open Scan)", "Stealth Scan (Half Open Scan)",
                "FIN Scan", "Null Scan", "XMAS Scan", "Maimon Scan", "ACK Flag Scan",
                "TTL Based Scan", "Window Scan"
            ]
            try:
                ports_val = parse_ports(ports)
            except Exception as e:
                self.progress['value'] = 0
                self.progress.pack_forget()
                self.scan_btn.config(state=tk.NORMAL)
                messagebox.showerror('Input Error', f'Port error: {e}')
                return
            scan_dict = {
                "ICMP Ping Scan": ["nmap", "-sn", target, "-v"],
                "UDP Ping Scan": ["nmap", "-sU", "-p", ports_val, target, "-v"],
                "SYN Scan (Full Open Scan)": ["nmap", "-sS", "-p", ports_val, target, "-v", "-T4"],
                "Stealth Scan (Half Open Scan)": ["nmap", "-sS", "--scanflags", "SYN", "-p", ports_val, target, "-v", "-T4"],
                "FIN Scan": ["nmap", "-sF", "-p", ports_val, target, "-v"],
                "Null Scan": ["nmap", "-sN", "-p", ports_val, target, "-v"],
                "XMAS Scan": ["nmap", "-sX", "-p", ports_val, target, "-v"],
                "Maimon Scan": ["nmap", "-sM", "-p", ports_val, target, "-v"],
                "ACK Flag Scan": ["nmap", "-sA", "-p", ports_val, target, "-v"],
                "TTL Based Scan": ["nmap", "--ttl", "128", "-sA", "-p", ports_val, target, "-v"],
                "Window Scan": ["nmap", "-sW", "-p", ports_val, target, "-v"]
            }
        self.progress['maximum'] = len(scan_names)
        progress = 0
        detailed = {}
        all_ports_status = {}
        all_hosts = set()
        for scan_name in scan_names:
            command = scan_dict[scan_name]
            output = run_scan(command)
            detailed[scan_name] = output
            if mode == 'host':
                from scanner import parse_nmap_hosts
                hosts = parse_nmap_hosts(output)
                all_hosts.update(hosts)
            else:
                scan_ports = parse_nmap_ports_all_statuses(output)
                for host, portlist in scan_ports.items():
                    if host not in all_ports_status:
                        all_ports_status[host] = []
                    all_ports_status[host].extend(portlist)
            progress += 1
            self.progress['value'] = progress
            self.progress.update_idletasks()
        if mode == 'host':
            summary = "Discovered hosts (sorted, unique):\n" + "\n".join(sorted(all_hosts))
            result = {"summary": summary, "detailed": detailed}
        else:
            for host in all_ports_status:
                all_ports_status[host] = sorted(set(all_ports_status[host]), key=lambda x: (x[0], x[1]))
            summary_lines = []
            for host in sorted(all_ports_status.keys()):
                summary_lines.append(f"\nHost: {host}")
                summary_lines.append(f"{'Port':>6} {'Proto':>6} {'Status':>10}")
                summary_lines.append('-'*26)
                for port, proto, status in all_ports_status[host]:
                    summary_lines.append(f"{port:>6} {proto:>6} {status:>10}")
            summary = "Port scan results (all statuses):\n" + ("\n".join(summary_lines) if summary_lines else "No ports found.")
            result = {"summary": summary, "detailed": detailed}
        self.progress['value'] = self.progress['maximum']
        self.progress.update_idletasks()
        self.summary_text.insert(tk.END, result['summary'])
        for scan_name, output in result['detailed'].items():
            self.detailed_text.insert(tk.END, f"\n=== {scan_name} ===\n{output}")
        self.summary_text.config(state=tk.NORMAL)
        self.detailed_text.config(state=tk.NORMAL)
        self.scan_btn.config(state=tk.NORMAL)
        self.progress.pack_forget()  # Hide progress bar after scan
        messagebox.showinfo('Scan Complete', 'Scan finished!')

    def copy_output(self):
        tab = self.tabs.index(self.tabs.select())
        text_widget = self.summary_text if tab == 0 else self.detailed_text
        self.root.clipboard_clear()
        self.root.clipboard_append(text_widget.get(1.0, tk.END))
        messagebox.showinfo('Copied', 'Output copied to clipboard!')

    def save_output(self):
        tab = self.tabs.index(self.tabs.select())
        text_widget = self.summary_text if tab == 0 else self.detailed_text
        content = text_widget.get(1.0, tk.END)
        filetypes = [('Text Files', '*.txt'), ('All Files', '*.*')]
        filename = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=filetypes)
        if filename:
            with open(filename, 'w') as f:
                f.write(content)
            messagebox.showinfo('Saved', f'Output saved to {filename}')


def main():
    root = tk.Tk()
    app = NyScanGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main() 