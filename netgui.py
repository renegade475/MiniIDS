#!/usr/bin/env python3
"""
Network Security Monitor - GUI Dashboard
Real-time intrusion detection with visual interface
"""

import sys
import json
import threading
import sqlite3
from datetime import datetime, timedelta
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QTableWidget, QTableWidgetItem,
    QTabWidget, QGroupBox, QGridLayout, QComboBox, QSpinBox,
    QProgressBar, QScrollArea, QFrame, QSplitter, QMessageBox
)
from PyQt5.QtCore import QTimer, QThread, pyqtSignal, Qt, QDateTime
from PyQt5.QtGui import QFont, QPalette, QColor, QPixmap, QPainter
from PyQt5.QtChart import QChart, QChartView, QLineSeries, QPieSeries, QValueAxis, QDateTimeAxis
import pyqtgraph as pg
from collections import defaultdict, deque
import time

# Import our network monitor
try:
    from network_monitor_core import NetworkSecurityMonitor
except ImportError:
    print("Please ensure network_monitor_core.py is in the same directory")
    sys.exit(1)

class MonitorThread(QThread):
    """Thread for running network monitoring"""
    alert_signal = pyqtSignal(str, str, str)  # type, severity, details
    stats_signal = pyqtSignal(dict)
    
    def __init__(self, interface=None):
        super().__init__()
        self.interface = interface
        self.monitor = None
        self.running = False
    
    def run(self):
        """Run the network monitor"""
        self.monitor = NetworkSecurityMonitor(
            interface=self.interface,
            alert_callback=self.handle_alert
        )
        self.running = True
        
        # Start statistics timer
        stats_timer = threading.Timer(5.0, self.emit_stats)
        stats_timer.daemon = True
        stats_timer.start()
        
        try:
            self.monitor.start_monitoring()
        except Exception as e:
            print(f"Monitor error: {e}")
    
    def handle_alert(self, alert_type, severity, details):
        """Handle alerts from monitor"""
        self.alert_signal.emit(alert_type, severity, details)
    
    def emit_stats(self):
        """Emit statistics periodically"""
        if self.monitor and self.running:
            try:
                stats = self.monitor.get_statistics()
                self.stats_signal.emit(stats)
                
                # Schedule next emission
                stats_timer = threading.Timer(5.0, self.emit_stats)
                stats_timer.daemon = True
                stats_timer.start()
            except:
                pass
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        if self.monitor:
            self.monitor.stop_monitoring()

class AlertWidget(QWidget):
    """Widget for displaying alerts"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.alerts = deque(maxlen=1000)  # Keep last 1000 alerts
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("Real-time Security Alerts")
        header.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(header)
        
        # Alert table
        self.alert_table = QTableWidget()
        self.alert_table.setColumnCount(4)
        self.alert_table.setHorizontalHeaderLabels(["Time", "Type", "Severity", "Details"])
        
        # Set column widths
        self.alert_table.setColumnWidth(0, 150)
        self.alert_table.setColumnWidth(1, 200)
        self.alert_table.setColumnWidth(2, 100)
        self.alert_table.setColumnWidth(3, 400)
        
        layout.addWidget(self.alert_table)
        
        # Clear button
        clear_btn = QPushButton("Clear Alerts")
        clear_btn.clicked.connect(self.clear_alerts)
        layout.addWidget(clear_btn)
        
        self.setLayout(layout)
    
    def add_alert(self, alert_type, severity, details):
        """Add new alert to the table"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Add to internal storage
        self.alerts.append({
            'timestamp': timestamp,
            'type': alert_type,
            'severity': severity,
            'details': details
        })
        
        # Add to table
        row_count = self.alert_table.rowCount()
        self.alert_table.insertRow(0)  # Insert at top
        
        self.alert_table.setItem(0, 0, QTableWidgetItem(timestamp))
        self.alert_table.setItem(0, 1, QTableWidgetItem(alert_type))
        
        # Color code severity
        severity_item = QTableWidgetItem(severity)
        if severity == "HIGH":
            severity_item.setBackground(QColor(255, 100, 100))
        elif severity == "MEDIUM":
            severity_item.setBackground(QColor(255, 255, 100))
        else:
            severity_item.setBackground(QColor(200, 255, 200))
        
        self.alert_table.setItem(0, 2, severity_item)
        self.alert_table.setItem(0, 3, QTableWidgetItem(details))
        
        # Limit table size
        if row_count > 100:
            self.alert_table.removeRow(100)
    
    def clear_alerts(self):
        """Clear all alerts"""
        self.alert_table.setRowCount(0)
        self.alerts.clear()

class StatsWidget(QWidget):
    """Widget for displaying statistics"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.traffic_data = defaultdict(list)
        self.time_data = deque(maxlen=100)
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("Network Statistics")
        header.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(header)
        
        # Statistics grid
        stats_group = QGroupBox("Current Statistics")
        stats_layout = QGridLayout()
        
        self.total_alerts_label = QLabel("Total Alerts: 0")
        self.high_alerts_label = QLabel("High Severity: 0")
        self.medium_alerts_label = QLabel("Medium Severity: 0")
        self.low_alerts_label = QLabel("Low Severity: 0")
        
        stats_layout.addWidget(self.total_alerts_label, 0, 0)
        stats_layout.addWidget(self.high_alerts_label, 0, 1)
        stats_layout.addWidget(self.medium_alerts_label, 1, 0)
        stats_layout.addWidget(self.low_alerts_label, 1, 1)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Traffic graph
        self.traffic_plot = pg.PlotWidget()
        self.traffic_plot.setLabel('left', 'Packets/sec')
        self.traffic_plot.setLabel('bottom', 'Time')
        self.traffic_plot.setTitle('Network Traffic')
        layout.addWidget(self.traffic_plot)
        
        # Protocol distribution
        self.protocol_table = QTableWidget()
        self.protocol_table.setColumnCount(3)
        self.protocol_table.setHorizontalHeaderLabels(["Protocol", "Count", "Avg Size"])
        layout.addWidget(self.protocol_table)
        
        self.setLayout(layout)
    
    def update_stats(self, stats):
        """Update statistics display"""
        # Update alert counts
        alerts = stats.get('alerts', {})
        total_alerts = 0
        high_count = medium_count = low_count = 0
        
        for alert_type, severities in alerts.items():
            for severity, count in severities.items():
                total_alerts += count
                if severity == "HIGH":
                    high_count += count
                elif severity == "MEDIUM":
                    medium_count += count
                else:
                    low_count += count
        
        self.total_alerts_label.setText(f"Total Alerts: {total_alerts}")
        self.high_alerts_label.setText(f"High Severity: {high_count}")
        self.medium_alerts_label.setText(f"Medium Severity: {medium_count}")
        self.low_alerts_label.setText(f"Low Severity: {low_count}")
        
        # Update protocol table
        traffic = stats.get('traffic', {})
        self.protocol_table.setRowCount(len(traffic))
        
        for i, (protocol, data) in enumerate(traffic.items()):
            self.protocol_table.setItem(i, 0, QTableWidgetItem(protocol))
            self.protocol_table.setItem(i, 1, QTableWidgetItem(str(data['count'])))
            self.protocol_table.setItem(i, 2, QTableWidgetItem(f"{data['avg_size']:.1f}"))
        
        # Update traffic graph
        current_time = time.time()
        self.time_data.append(current_time)
        
        total_traffic = sum(data['count'] for data in traffic.values())
        if len(self.time_data) > 1:
            # Calculate packets per second
            time_diff = self.time_data[-1] - self.time_data[-2]
            if time_diff > 0:
                pps = total_traffic / time_diff
                self.traffic_data['pps'].append(pps)
            else:
                self.traffic_data['pps'].append(0)
        else:
            self.traffic_data['pps'].append(0)
        
        # Keep only recent data
        if len(self.traffic_data['pps']) > 100:
            self.traffic_data['pps'] = self.traffic_data['pps'][-100:]
        
        # Update plot
        if len(self.traffic_data['pps']) > 1:
            x_data = list(range(len(self.traffic_data['pps'])))
            self.traffic_plot.clear()
            self.traffic_plot.plot(x_data, self.traffic_data['pps'], pen='g')

class ConfigWidget(QWidget):
    """Widget for configuration settings"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("Monitor Configuration")
        header.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(header)
        
        # Configuration options
        config_group = QGroupBox("Detection Thresholds")
        config_layout = QGridLayout()
        
        config_layout.addWidget(QLabel("Port scan threshold:"), 0, 0)
        self.port_scan_spin = QSpinBox()
        self.port_scan_spin.setRange(5, 100)
        self.port_scan_spin.setValue(10)
        config_layout.addWidget(self.port_scan_spin, 0, 1)
        
        config_layout.addWidget(QLabel("DNS flood threshold:"), 1, 0)
        self.dns_flood_spin = QSpinBox()
        self.dns_flood_spin.setRange(10, 500)
        self.dns_flood_spin.setValue(50)
        config_layout.addWidget(self.dns_flood_spin, 1, 1)
        
        config_layout.addWidget(QLabel("ARP threshold:"), 2, 0)
        self.arp_spin = QSpinBox()
        self.arp_spin.setRange(3, 50)
        self.arp_spin.setValue(5)
        config_layout.addWidget(self.arp_spin, 2, 1)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Export options
        export_group = QGroupBox("Export Options")
        export_layout = QVBoxLayout()
        
        export_siem_btn = QPushButton("Export to SIEM Format")
        export_siem_btn.clicked.connect(self.export_siem)
        export_layout.addWidget(export_siem_btn)
        
        export_json_btn = QPushButton("Export Raw Data")
        export_json_btn.clicked.connect(self.export_json)
        export_layout.addWidget(export_json_btn)
        
        export_group.setLayout(export_layout)
        layout.addWidget(export_group)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def export_siem(self):
        """Export data in SIEM format"""
        # This would be implemented with the monitor instance
        QMessageBox.information(self, "Export", "SIEM export functionality would be implemented here")
    
    def export_json(self):
        """Export raw data"""
        QMessageBox.information(self, "Export", "JSON export functionality would be implemented here")

class NetworkSecurityGUI(QMainWindow):
    """Main GUI application"""
    
    def __init__(self):
        super().__init__()
        self.monitor_thread = None
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("Advanced Network Security Monitor")
        self.setGeometry(100, 100, 1200, 800)
        
        # Set dark theme
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #555555;
                border-radius: 5px;
                margin-top: 1ex;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QPushButton {
                background-color: #4CAF50;
                border: none;
                color: white;
                padding: 8px 16px;
                text-align: center;
                font-size: 14px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3d8b40;
            }
            QTableWidget {
                background-color: #3c3c3c;
                alternate-background-color: #404040;
                selection-background-color: #4CAF50;
            }
            QHeaderView::section {
                background-color: #555555;
                padding: 8px;
                border: 1px solid #666666;
                font-weight: bold;
            }
        """)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout()
        
        # Control panel
        control_panel = self.create_control_panel()
        main_layout.addWidget(control_panel)
        
        # Tab widget for different views
        self.tab_widget = QTabWidget()
        
        # Create tabs
        self.alert_widget = AlertWidget()
        self.stats_widget = StatsWidget()
        self.config_widget = ConfigWidget()
        
        self.tab_widget.addTab(self.alert_widget, "🚨 Alerts")
        self.tab_widget.addTab(self.stats_widget, "📊 Statistics")
        self.tab_widget.addTab(self.config_widget, "⚙️ Configuration")
        
        main_layout.addWidget(self.tab_widget)
        
        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready - Click Start Monitoring to begin")
        
        central_widget.setLayout(main_layout)
    
    def create_control_panel(self):
        """Create the control panel"""
        control_group = QGroupBox("Monitor Control")
        control_layout = QHBoxLayout()
        
        # Interface selection
        control_layout.addWidget(QLabel("Interface:"))
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(["auto", "eth0", "wlan0", "lo"])
        control_layout.addWidget(self.interface_combo)
        
        # Control buttons
        self.start_btn = QPushButton("🚀 Start Monitoring")
        self.start_btn.clicked.connect(self.start_monitoring)
        self.start_btn.setStyleSheet("QPushButton { background-color: #4CAF50; }")
        control_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("⏹️ Stop Monitoring")
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("QPushButton { background-color: #f44336; }")
        control_layout.addWidget(self.stop_btn)
        
        # Status indicator
        self.status_indicator = QLabel("🔴 Stopped")
        self.status_indicator.setStyleSheet("QLabel { color: #f44336; font-weight: bold; }")
        control_layout.addWidget(self.status_indicator)
        
        control_layout.addStretch()
        
        # Export button
        export_btn = QPushButton("📤 Export Data")
        export_btn.clicked.connect(self.export_data)
        control_layout.addWidget(export_btn)
        
        control_group.setLayout(control_layout)
        return control_group
    
    def start_monitoring(self):
        """Start network monitoring"""
        if self.monitor_thread and self.monitor_thread.isRunning():
            return
        
        interface = self.interface_combo.currentText()
        if interface == "auto":
            interface = None
        
        self.monitor_thread = MonitorThread(interface)
        self.monitor_thread.alert_signal.connect(self.handle_alert)
        self.monitor_thread.stats_signal.connect(self.handle_stats)
        self.monitor_thread.start()
        
        # Update UI
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_indicator.setText("🟢 Monitoring")
        self.status_indicator.setStyleSheet("QLabel { color: #4CAF50; font-weight: bold; }")
        self.status_bar.showMessage("Network monitoring active...")
        
        # Show notification
        QMessageBox.information(self, "Monitor Started", 
                               "Network security monitoring has started.\n"
                               "Alerts will appear in the Alerts tab.")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        if self.monitor_thread:
            self.monitor_thread.stop()
            self.monitor_thread.wait(5000)  # Wait up to 5 seconds
            
        # Update UI
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_indicator.setText("🔴 Stopped")
        self.status_indicator.setStyleSheet("QLabel { color: #f44336; font-weight: bold; }")
        self.status_bar.showMessage("Network monitoring stopped")
    
    def handle_alert(self, alert_type, severity, details):
        """Handle incoming alerts"""
        self.alert_widget.add_alert(alert_type, severity, details)
        
        # Update status bar with latest alert
        self.status_bar.showMessage(f"Latest: {alert_type} ({severity}) - {details[:50]}...")
        
        # Flash the alerts tab if not currently selected
        if self.tab_widget.currentIndex() != 0:
            self.tab_widget.setTabText(0, "🚨 Alerts (!)")
    
    def handle_stats(self, stats):
        """Handle statistics updates"""
        self.stats_widget.update_stats(stats)
    
    def export_data(self):
        """Export monitoring data"""
        if not self.monitor_thread or not self.monitor_thread.monitor:
            QMessageBox.warning(self, "Export Error", 
                               "No monitoring data available. Start monitoring first.")
            return
        
        try:
            # Export to SIEM format
            self.monitor_thread.monitor.export_to_siem("network_security_export.json")
            
            # Also export current alerts
            alerts_data = {
                'alerts': list(self.alert_widget.alerts),
                'export_time': datetime.now().isoformat(),
                'total_alerts': len(self.alert_widget.alerts)
            }
            
            with open("gui_alerts_export.json", "w") as f:
                json.dump(alerts_data, f, indent=2)
            
            QMessageBox.information(self, "Export Complete", 
                                   "Data exported successfully:\n"
                                   "- network_security_export.json (SIEM format)\n"
                                   "- gui_alerts_export.json (GUI alerts)")
            
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export data: {str(e)}")
    
    def closeEvent(self, event):
        """Handle application close"""
        if self.monitor_thread and self.monitor_thread.isRunning():
            reply = QMessageBox.question(self, "Confirm Exit", 
                                       "Monitoring is still active. Stop monitoring and exit?",
                                       QMessageBox.Yes | QMessageBox.No)
            
            if reply == QMessageBox.Yes:
                self.stop_monitoring()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()

def main():
    """Main function to run the application"""
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("Network Security Monitor")
    app.setApplicationVersion("1.0")
    
    # Create and show the main window
    window = NetworkSecurityGUI()
    window.show()
    
    # Run the application
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()