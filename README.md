# Network Security Monitor

A real-time intrusion detection and traffic monitoring system built with Python. This tool combines packet-level inspection, rule-based threat detection, and an interactive GUI dashboard to help monitor and secure local networks against common attacks.

## Features

- Live packet capture and analysis using Scapy
- Detection of:
  - ARP spoofing
  - Port scanning
  - DNS poisoning and flooding
  - Potential data exfiltration patterns
- Real-time security alerts with severity levels
- Interactive GUI dashboard using PyQt5 and pyqtgraph
- Logging to a local SQLite database (`network_monitor.db`)
- Data export options in JSON and SIEM-compatible formats
- Auto-generated configuration file (`monitor_config.json`)

## Components

- `netgui.py` - Graphical interface for starting/stopping monitoring, viewing alerts, and exporting data.
- `network_monitor_core.py` - Core engine that captures and analyzes network traffic.
- `net_setup.py` - Setup script that installs dependencies, checks system compatibility, and generates a sample config.

## Installation

1. Clone or download the project to your system.
2. Navigate to the project directory in terminal.

   ```bash
   cd C:\project\net
   ```

3. Run the setup script:

   ```bash
   python net_setup.py
   ```

4. (Optional) Install the missing chart dependency:

   ```bash
   pip install PyQtChart
   ```

5. To launch the GUI:

   ```bash
   python netgui.py
   ```

   > Note: Running as administrator (Windows) or with sudo (Linux/macOS) is required for packet capture.

## Running as a Standalone Application

To build a standalone `.exe`:

1. Install PyInstaller:

   ```bash
   pip install pyinstaller
   ```

2. Generate the executable:

   ```bash
   pyinstaller --noconfirm --onefile --windowed netgui.py
   ```

3. The compiled binary will be available in the `dist/` folder.

## Permissions

Packet sniffing requires elevated privileges:

- **Linux/macOS**: Use `sudo`, or assign CAP_NET_RAW to Python binary.
- **Windows**:
  - Run as Administrator.
  - Ensure WinPcap or Npcap is installed.

## Exporting Data

- Export alerts and statistics in SIEM-compatible JSON format using the GUI.
- Files generated:
  - `network_security_export.json` – for SIEM tools.
  - `gui_alerts_export.json` – user-friendly export of GUI data.

## Requirements

- Python 3.7+
- scapy >= 2.4.5
- PyQt5 >= 5.15.0
- PyQtChart
- pyqtgraph >= 0.12.0
- beautifulsoup4 >= 4.9.0
- requests >= 2.25.0

Install all dependencies via:

```bash
pip install -r requirements.txt
```

## License

This project is open for educational and research purposes. Please ensure any usage in production systems complies with applicable security laws and network monitoring policies.
