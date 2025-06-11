#!/usr/bin/env python3
"""
Network Security Monitor - Setup and Installation Script
"""

import os
import sys
import subprocess
import platform

def check_root():
    """Check if running with sufficient privileges"""
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        return os.geteuid() == 0

def install_requirements():
    """Install required Python packages"""
    requirements = [
        "scapy>=2.4.5",
        "PyQt5>=5.15.0",
        "pyqtgraph>=0.12.0",
        "beautifulsoup4>=4.9.0",
        "requests>=2.25.0"
    ]
    
    print("Installing required packages...")
    for req in requirements:
        try:
            print(f"Installing {req}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", req])
            print(f"✓ {req} installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to install {req}: {e}")
            return False
    
    return True

def setup_permissions():
    """Setup network monitoring permissions"""
    system = platform.system()
    
    if system == "Linux":
        print("\nSetting up Linux permissions...")
        print("For packet capture, you need to either:")
        print("1. Run as root (sudo python3 network_monitor_gui.py)")
        print("2. Or set capabilities for Python:")
        print("   sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)")
        print("\nNote: Option 2 allows running without sudo but affects all Python scripts")
        
    elif system == "Darwin":  # macOS
        print("\nSetting up macOS permissions...")
        print("For packet capture, you need to:")
        print("1. Run as root (sudo python3 network_monitor_gui.py)")
        print("2. Or add your user to the 'access_bpf' group (requires admin)")
        
    elif system == "Windows":
        print("\nSetting up Windows permissions...")
        print("For packet capture, you need to:")
        print("1. Run as Administrator")
        print("2. Install WinPcap or Npcap driver")
        print("3. Ensure Windows Defender allows the application")

def create_sample_config():
    """Create sample configuration file"""
    config = {
        "detection_thresholds": {
            "port_scan_threshold": 10,
            "dns_threshold": 50,
            "arp_threshold": 5,
            "time_window": 60
        },
        "monitoring": {
            "default_interface": "auto",
            "packet_timeout": 15,
            "max_alerts": 1000
        },
        "export": {
            "siem_format": "cef",
            "auto_export": False,
            "export_interval": 3600
        }
    }
    
    try:
        import json
        with open("monitor_config.json", "w") as f:
            json.dump(config, f, indent=2)
        print("✓ Created sample configuration file: monitor_config.json")
    except Exception as e:
        print(f"✗ Failed to create config file: {e}")

def check_network_interfaces():
    """Check available network interfaces"""
    try:
        import scapy.all as scapy
        interfaces = scapy.get_if_list()
        print(f"\nAvailable network interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")
        return interfaces
    except ImportError:
        print("Scapy not installed - cannot check interfaces")
        return []

def run_system_checks():
    """Run various system compatibility checks"""
    print("Running system compatibility checks...\n")
    
    # Check Python version
    python_version = sys.version_info
    if python_version.major == 3 and python_version.minor >= 7:
        print(f"✓ Python version: {python_version.major}.{python_version.minor}")
    else:
        print(f"✗ Python version {python_version.major}.{python_version.minor} not supported")
        print("  Requires Python 3.7+")
        return False
    
    # Check operating system
    system = platform.system()
    print(f"✓ Operating System: {system} {platform.release()}")
    
    # Check privileges
    if check_root():
        print("✓ Running with administrative privileges")
    else:
        print("⚠ Not running with administrative privileges")
        print("  Packet capture may require elevated permissions")
    
    return True

def main():
    """Main setup function"""
    print("=" * 60)
    print("Network Security Monitor - Setup Script")
    print("=" * 60)
    
    # Run system checks
    if not run_system_checks():
        print("\nSystem compatibility check failed!")
        return False
    
    # Install requirements
    print("\n" + "=" * 40)
    print("Installing Dependencies")
    print("=" * 40)
    
    if not install_requirements():
        print("Failed to install required packages!")
        return False
    
    # Check network interfaces
    print("\n" + "=" * 40)
    print("Network Interface Check")
    print("=" * 40)
    check_network_interfaces()
    
    # Setup permissions
    print("\n" + "=" * 40)
    print("Permission Setup")
    print("=" * 40)
    setup_permissions()
    
    # Create config file
    print("\n" + "=" * 40)
    print("Configuration Setup")
    print("=" * 40)
    create_sample_config()
    
    # Final instructions
    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)
    print("\nTo run the Network Security Monitor:")
    print("1. GUI Version: python3 network_monitor_gui.py")
    print("2. CLI Version: python3 network_monitor_core.py")
    print("\nNote: Packet capture typically requires administrative privileges")
    print("On Linux/macOS: sudo python3 network_monitor_gui.py")
    print("On Windows: Run Command Prompt as Administrator")
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        if not success:
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nSetup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nSetup failed with error: {e}")
        sys.exit(1)