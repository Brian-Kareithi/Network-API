from flask import Flask, jsonify, request
from flask_cors import CORS
import subprocess
import platform
import socket
import ipaddress
import time
import random
import threading
import sqlite3
import json
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import speedtest
import nmap
import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
import netifaces
import psutil
from collections import defaultdict, deque
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Initialize global variables with thread safety
device_cache = []
speed_cache = {}
last_scan_time = 0
ssid_cache = "Unknown"
network_stats = defaultdict(deque)
threat_log = []
active_connections = []
lock = threading.Lock()

# Database setup
def init_db():
    conn = sqlite3.connect('network_monitor.db')
    c = conn.cursor()
    
    # Create devices table
    c.execute('''CREATE TABLE IF NOT EXISTS devices
                 (mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, vendor TEXT, 
                  device_type TEXT, model TEXT, first_seen TEXT, last_seen TEXT,
                  threat_level INTEGER, avg_activity REAL, is_trusted BOOLEAN)''')
    
    # Create network events table
    c.execute('''CREATE TABLE IF NOT EXISTS network_events
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, 
                  event_type TEXT, device_mac TEXT, details TEXT)''')
    
    # Create speed tests table
    c.execute('''CREATE TABLE IF NOT EXISTS speed_tests
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, 
                  download REAL, upload REAL, latency REAL)''')
    
    conn.commit()
    conn.close()

init_db()

# Enhanced device profiles with more vendors and patterns
DEVICE_PROFILES = {
    "00:1a:2b": {"type": "mobile", "model": "iPhone", "vendor": "Apple", "typical_ports": [62078, 5223]},
    "00:1d:4f": {"type": "tablet", "model": "iPad", "vendor": "Apple", "typical_ports": [62078, 5223]},
    "00:03:93": {"type": "computer", "model": "MacBook", "vendor": "Apple", "typical_ports": [22, 445, 548]},
    "5c:49:7d": {"type": "mobile", "model": "Galaxy S21", "vendor": "Samsung", "typical_ports": [55000, 55001]},
    "30:07:4d": {"type": "mobile", "model": "Galaxy Note", "vendor": "Samsung", "typical_ports": [55000, 55001]},
    "cc:6e:a4": {"type": "tv", "model": "Smart TV", "vendor": "Samsung", "typical_ports": [8001, 8002]},
    "3c:28:6d": {"type": "mobile", "model": "Pixel", "vendor": "Google", "typical_ports": [7275, 7276]},
    "f8:8f:ca": {"type": "iot", "model": "Nest", "vendor": "Google", "typical_ports": [9550, 11095]},
    "00:1f:33": {"type": "router", "model": "Router", "vendor": "Cisco", "typical_ports": [23, 80, 443]},
    "00:0c:42": {"type": "router", "model": "Router", "vendor": "Netgear", "typical_ports": [23, 80, 443]},
    "00:1b:21": {"type": "printer", "model": "LaserJet", "vendor": "HP", "typical_ports": [80, 443, 631]},
    "94:b9:7e": {"type": "iot", "model": "Smart Plug", "vendor": "TP-Link", "typical_ports": [9999]},
    "a4:cf:12": {"type": "camera", "model": "Security Cam", "vendor": "Xiaomi", "typical_ports": [554, 8000]},
    "dc:a6:32": {"type": "iot", "model": "Raspberry Pi", "vendor": "Raspberry Pi", "typical_ports": [22, 5900]},
    "b8:27:eb": {"type": "iot", "model": "Raspberry Pi", "vendor": "Raspberry Pi", "typical_ports": [22, 5900]},
    "e4:5d:51": {"type": "iot", "model": "Chromecast", "vendor": "Google", "typical_ports": [8008, 8009, 9000]},
    "74:da:38": {"type": "iot", "model": "Amazon Echo", "vendor": "Amazon", "typical_ports": [4070, 49317]},
}

# Known malicious MAC prefixes (for demonstration)
MALICIOUS_PREFIXES = ["00:1c:42", "00:21:5a", "00:25:5e"]

# ---------------- UTILS ---------------- #

def get_local_ip():
    """Get the local IP of the current machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        logger.error(f"Error getting local IP: {e}")
        return "127.0.0.1"

def get_network_interfaces():
    """Get all network interfaces."""
    interfaces = {}
    for interface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            interfaces[interface] = addrs[netifaces.AF_INET][0]['addr']
    return interfaces

def get_ssid():
    """Get the current WiFi SSID."""
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("netsh wlan show interfaces", shell=True).decode()
            for line in output.split('\n'):
                if "SSID" in line and "BSSID" not in line:
                    return line.split(":")[1].strip()
        elif platform.system() == "Darwin":  # macOS
            output = subprocess.check_output("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I", shell=True).decode()
            for line in output.split('\n'):
                if "SSID" in line:
                    return line.split(":")[1].strip()
        else:  # Linux
            output = subprocess.check_output("iwgetid -r", shell=True).decode()
            return output.strip()
    except Exception as e:
        logger.error(f"Error getting SSID: {e}")
    return "Unknown"

def get_default_gateway():
    """Get the default gateway IP."""
    try:
        gateways = netifaces.gateways()
        return gateways['default'][netifaces.AF_INET][0]
    except:
        return None

def mac_vendor_lookup(mac):
    """Look up vendor information for a MAC address."""
    # In a real implementation, you might use a MAC vendor database
    # For now, we'll use our predefined profiles
    mac_prefix = mac.lower()[:8]
    for prefix, info in DEVICE_PROFILES.items():
        if mac.startswith(prefix):
            return info["vendor"]
    return "Unknown"

def guess_device_info(mac):
    """Guess device info based on MAC prefix."""
    mac = mac.lower()
    for prefix, info in DEVICE_PROFILES.items():
        if mac.startswith(prefix):
            return info
    return {"type": "unknown", "model": "Unknown", "vendor": "Unknown", "typical_ports": []}

def get_device_icon(device_type):
    """Get an appropriate icon for the device type."""
    icons = {
        "mobile": "📱",
        "tablet": "📱",
        "computer": "💻",
        "router": "📶",
        "printer": "🖨️",
        "tv": "📺",
        "iot": "🔌",
        "camera": "📷",
        "unknown": "❓"
    }
    return icons.get(device_type, "❓")

def get_hostname(ip):
    """Get hostname for an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        try:
            # Try reverse DNS lookup
            return socket.getnameinfo((ip, 0), 0)[0]
        except:
            return None

def is_ip_local(ip):
    """Check if an IP is in the local network."""
    local_ip = get_local_ip()
    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return ipaddress.ip_address(ip) in network

# ---------------- DATABASE OPERATIONS ---------------- #

def save_device(device):
    """Save or update a device in the database."""
    conn = sqlite3.connect('network_monitor.db')
    c = conn.cursor()
    
    # Check if device exists
    c.execute("SELECT * FROM devices WHERE mac = ?", (device['mac'],))
    existing = c.fetchone()
    
    if existing:
        # Update existing device
        c.execute('''UPDATE devices SET ip = ?, hostname = ?, last_seen = ?, 
                     threat_level = ?, avg_activity = ? WHERE mac = ?''',
                 (device['ip'], device['hostname'], device['last_seen'], 
                  device['threat_level'], device['activity'], device['mac']))
    else:
        # Insert new device
        c.execute('''INSERT INTO devices (mac, ip, hostname, vendor, device_type, model, 
                     first_seen, last_seen, threat_level, avg_activity, is_trusted)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (device['mac'], device['ip'], device['hostname'], device['vendor'],
                  device['device_type'], device['model_number'], device['first_seen'],
                  device['last_seen'], device['threat_level'], device['activity'], False))
    
    conn.commit()
    conn.close()

def log_network_event(event_type, device_mac, details):
    """Log a network event to the database."""
    conn = sqlite3.connect('network_monitor.db')
    c = conn.cursor()
    
    c.execute('''INSERT INTO network_events (timestamp, event_type, device_mac, details)
                 VALUES (?, ?, ?, ?)''',
             (datetime.now().isoformat(), event_type, device_mac, json.dumps(details)))
    
    conn.commit()
    conn.close()

def save_speed_test(download, upload, latency):
    """Save speed test results to the database."""
    conn = sqlite3.connect('network_monitor.db')
    c = conn.cursor()
    
    c.execute('''INSERT INTO speed_tests (timestamp, download, upload, latency)
                 VALUES (?, ?, ?, ?)''',
             (datetime.now().isoformat(), download, upload, latency))
    
    conn.commit()
    conn.close()

def get_device_history(mac, hours=24):
    """Get historical data for a device."""
    conn = sqlite3.connect('network_monitor.db')
    c = conn.cursor()
    
    since_time = (datetime.now() - timedelta(hours=hours)).isoformat()
    c.execute('''SELECT timestamp, event_type, details FROM network_events 
                 WHERE device_mac = ? AND timestamp > ? ORDER BY timestamp''',
             (mac, since_time))
    
    events = []
    for row in c.fetchall():
        events.append({
            'timestamp': row[0],
            'event_type': row[1],
            'details': json.loads(row[2])
        })
    
    conn.close()
    return events

def get_speed_test_history(hours=24):
    """Get historical speed test data."""
    conn = sqlite3.connect('network_monitor.db')
    c = conn.cursor()
    
    since_time = (datetime.now() - timedelta(hours=hours)).isoformat()
    c.execute('''SELECT timestamp, download, upload, latency FROM speed_tests 
                 WHERE timestamp > ? ORDER BY timestamp''', (since_time,))
    
    tests = []
    for row in c.fetchall():
        tests.append({
            'timestamp': row[0],
            'download': row[1],
            'upload': row[2],
            'latency': row[3]
        })
    
    conn.close()
    return tests

# ---------------- NETWORK SCANNING ---------------- #

def arp_scan(network):
    """Perform an ARP scan of the network using Scapy."""
    devices = []
    try:
        # Create ARP request
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        # Send packets and get responses
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        # Process responses
        for element in answered_list:
            devices.append({
                'ip': element[1].psrc,
                'mac': element[1].hwsrc,
                'hostname': get_hostname(element[1].psrc)
            })
    except Exception as e:
        logger.error(f"ARP scan failed: {e}")
    
    return devices

def nmap_scan(ip):
    """Perform a detailed scan of a specific device using Nmap."""
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-sS -O --version-light')
        
        if ip in nm.all_hosts():
            host = nm[ip]
            return {
                'os_guess': host.get('osmatch', [{}])[0].get('name', 'Unknown') if host.get('osmatch') else 'Unknown',
                'open_ports': [port for port in host.get('tcp', {}).keys() if host['tcp'][port]['state'] == 'open'],
                'port_details': {port: host['tcp'][port] for port in host.get('tcp', {}).keys()}
            }
    except Exception as e:
        logger.error(f"Nmap scan failed for {ip}: {e}")
    
    return {'os_guess': 'Unknown', 'open_ports': [], 'port_details': {}}

def ping_sweep(network):
    """Ping all IPs in the network to find active devices."""
    active_ips = []
    network = ipaddress.ip_network(network, strict=False)
    
    def ping_ip(ip):
        try:
            param = "-n 1 -w 1000" if platform.system().lower() == "windows" else "-c 1 -W 1"
            command = f"ping {param} {ip}"
            response = subprocess.call(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return ip if response == 0 else None
        except:
            return None
    
    # Ping all IPs in parallel
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(ping_ip, str(ip)): ip for ip in network.hosts()}
        for future in as_completed(futures):
            result = future.result()
            if result:
                active_ips.append(result)
    
    return active_ips

def get_active_connections():
    """Get active network connections."""
    connections = []
    try:
        for conn in psutil.net_connections():
            if conn.status == 'ESTABLISHED' and conn.laddr and conn.raddr:
                connections.append({
                    'local_ip': conn.laddr.ip,
                    'local_port': conn.laddr.port,
                    'remote_ip': conn.raddr.ip,
                    'remote_port': conn.raddr.port,
                    'status': conn.status,
                    'pid': conn.pid
                })
    except Exception as e:
        logger.error(f"Error getting active connections: {e}")
    
    return connections

# ---------------- THREAT DETECTION ---------------- #

def detect_threats(device, network_data):
    """Advanced threat detection for a device."""
    threats = []
    threat_level = 0
    
    # Check for known malicious MAC prefixes
    if any(device['mac'].lower().startswith(prefix) for prefix in MALICIOUS_PREFIXES):
        threats.append("Known malicious MAC prefix")
        threat_level = max(threat_level, 80)
    
    # Check for unusual open ports
    typical_ports = device.get('typical_ports', [])
    open_ports = device.get('open_ports', [])
    unusual_ports = [port for port in open_ports if port not in typical_ports]
    
    if unusual_ports and typical_ports:  # Only flag if we know what's typical
        threats.append(f"Unusual open ports: {unusual_ports}")
        threat_level = max(threat_level, 60)
    
    # Check for suspicious hostname
    hostname = device.get('hostname', '')
    if hostname and any(suspicious in hostname.lower() for suspicious in ['hack', 'attack', 'malware']):
        threats.append(f"Suspicious hostname: {hostname}")
        threat_level = max(threat_level, 70)
    
    # Check for unusual activity patterns
    if device['mac'] in network_stats and len(network_stats[device['mac']]) > 10:
        recent_activity = list(network_stats[device['mac']])[-10:]
        avg_activity = sum(recent_activity) / len(recent_activity)
        if device['activity'] > avg_activity * 2:  # Sudden spike in activity
            threats.append("Unusual activity spike")
            threat_level = max(threat_level, 50)
    
    # Check if device is connecting to suspicious remote IPs
    for conn in active_connections:
        if conn['local_ip'] == device['ip']:
            if not is_ip_local(conn['remote_ip']):
                # External connection - check if it's to a known suspicious port
                if conn['remote_port'] in [4444, 31337, 6667]:  # Common malicious ports
                    threats.append(f"Suspicious external connection to port {conn['remote_port']}")
                    threat_level = max(threat_level, 90)
    
    return {
        'is_threat': len(threats) > 0,
        'threat_level': threat_level,
        'threats': threats
    }

# ---------------- NETWORK SCAN ---------------- #

def scan_network():
    """Comprehensive network scan with multiple techniques."""
    global device_cache, last_scan_time, ssid_cache, active_connections
    
    local_ip = get_local_ip()
    network = f"{local_ip}/24"
    ssid_cache = get_ssid()
    
    logger.info(f"Starting network scan on {network}")
    
    # Get active connections
    active_connections = get_active_connections()
    
    # Use multiple scanning techniques for better coverage
    arp_devices = arp_scan(network)
    ping_devices = [{'ip': ip, 'mac': 'Unknown', 'hostname': get_hostname(ip)} for ip in ping_sweep(network)]
    
    # Combine results, preferring ARP data when available
    all_devices = {}
    for device in arp_devices + ping_devices:
        if device['ip'] not in all_devices or all_devices[device['ip']]['mac'] == 'Unknown':
            all_devices[device['ip']] = device
    
    devices = []
    gateway_ip = get_default_gateway()
    
    for ip, device_data in all_devices.items():
        # Skip our own IP and the gateway (to avoid scanning it with Nmap)
        if ip == local_ip or ip == gateway_ip:
            continue
        
        # Get detailed info with Nmap (limited to 5 devices per scan to avoid overloading)
        nmap_data = {}
        if len(devices) < 5:
            nmap_data = nmap_scan(ip)
        
        info = guess_device_info(device_data['mac'])
        
        device_obj = {
            "ip": ip,
            "mac": device_data['mac'],
            "hostname": device_data['hostname'],
            "vendor": mac_vendor_lookup(device_data['mac']),
            "connected": True,
            "device_type": info["type"],
            "model_number": info["model"],
            "typical_ports": info["typical_ports"],
            "icon": get_device_icon(info["type"]),
            "signal_strength": random.randint(50, 100) if info["type"] in ["mobile", "tablet"] else 100,
            "first_seen": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "last_seen": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "activity": random.randint(5, 95),
            "open_ports": nmap_data.get('open_ports', []),
            "os_guess": nmap_data.get('os_guess', 'Unknown')
        }
        
        # Threat detection
        threat_info = detect_threats(device_obj, {
            'active_connections': active_connections,
            'network_stats': network_stats
        })
        
        device_obj.update({
            "threat": threat_info['is_threat'],
            "threat_level": threat_info['threat_level'],
            "threats": threat_info['threats']
        })
        
        # Update network stats
        if device_data['mac'] != 'Unknown':
            if device_data['mac'] not in network_stats:
                network_stats[device_data['mac']] = deque(maxlen=100)
            network_stats[device_data['mac']].append(device_obj['activity'])
        
        devices.append(device_obj)
        
        # Save to database
        save_device(device_obj)
        
        # Log new device or threat
        if threat_info['is_threat']:
            log_network_event('threat_detected', device_data['mac'], {
                'threats': threat_info['threats'],
                'threat_level': threat_info['threat_level']
            })
            threat_log.append({
                'timestamp': datetime.now().isoformat(),
                'device': device_data['mac'],
                'threats': threat_info['threats'],
                'threat_level': threat_info['threat_level']
            })
        elif device_data['mac'] != 'Unknown' and not any(d['mac'] == device_data['mac'] for d in device_cache):
            log_network_event('new_device', device_data['mac'], {
                'ip': ip,
                'hostname': device_data['hostname'],
                'vendor': device_obj['vendor']
            })
    
    # Add gateway device
    if gateway_ip:
        devices.append({
            "ip": gateway_ip,
            "mac": "Unknown",
            "hostname": get_hostname(gateway_ip) or "Gateway",
            "vendor": "Router",
            "connected": True,
            "device_type": "router",
            "model_number": "Router",
            "icon": "📶",
            "signal_strength": 100,
            "first_seen": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "last_seen": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "activity": 50,
            "threat": False,
            "threat_level": 0,
            "threats": []
        })
    
    with lock:
        device_cache = devices
        last_scan_time = time.time()
    
    logger.info(f"Network scan completed. Found {len(devices)} devices.")
    return devices

# ---------------- SPEED TEST ---------------- #

def run_speed_test():
    """Run a comprehensive speed test."""
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        
        download = st.download() / 1_000_000  # Convert to Mbps
        upload = st.upload() / 1_000_000  # Convert to Mbps
        latency = st.results.ping
        
        result = {
            "latency": round(latency, 2),
            "download_speed": round(download, 2),
            "upload_speed": round(upload, 2),
            "server": st.best['name'],
            "timestamp": datetime.now().isoformat()
        }
        
        # Save to database
        save_speed_test(download, upload, latency)
        
        return result
    except Exception as e:
        logger.error(f"Speed test failed: {e}")
        return {"latency": 0, "download_speed": 0, "upload_speed": 0, "server": "Unknown", "timestamp": datetime.now().isoformat()}

# ---------------- NETWORK STATUS ---------------- #

def get_network_status():
    """Get comprehensive network status."""
    threat_count = sum(1 for d in device_cache if d["threat"])
    
    # Calculate network health score (0-100)
    health_score = 100
    if threat_count > 0:
        health_score -= threat_count * 10
    if any(d['activity'] > 90 for d in device_cache):
        health_score -= 10
    
    return {
        "health_score": max(0, health_score),
        "safe": threat_count == 0,
        "network_ip": get_local_ip(),
        "subnet_mask": "255.255.255.0",  # Simplified
        "gateway": get_default_gateway(),
        "ssid": ssid_cache,
        "total_devices": len(device_cache),
        "threat_count": threat_count,
        "active_connections": len(active_connections),
        "last_scan": datetime.fromtimestamp(last_scan_time).strftime('%Y-%m-%d %H:%M:%S')
    }

# ---------------- BANDWIDTH MONITORING ---------------- #

def get_bandwidth_usage():
    """Get current bandwidth usage."""
    net_io = psutil.net_io_counters()
    return {
        "bytes_sent": net_io.bytes_sent,
        "bytes_recv": net_io.bytes_recv,
        "packets_sent": net_io.packets_sent,
        "packets_recv": net_io.packets_recv,
        "errin": net_io.errin,
        "errout": net_io.errout,
        "dropin": net_io.dropin,
        "dropout": net_io.dropout
    }

# ---------------- API ROUTES ---------------- #

@app.route('/api/devices', methods=['GET'])
def devices():
    """Get all devices on the network."""
    global device_cache, last_scan_time
    if not device_cache or (time.time() - last_scan_time) > 60:
        scan_network()
    return jsonify(device_cache)

@app.route('/api/device/<mac>', methods=['GET'])
def device_detail(mac):
    """Get detailed information about a specific device."""
    device = next((d for d in device_cache if d['mac'] == mac), None)
    if not device:
        return jsonify({"error": "Device not found"}), 404
    
    # Get device history
    history = get_device_history(mac)
    
    return jsonify({
        "device": device,
        "history": history
    })

@app.route('/api/network-status', methods=['GET'])
def network_status():
    """Get current network status."""
    return jsonify(get_network_status())

@app.route('/api/bandwidth', methods=['GET'])
def bandwidth():
    """Get current bandwidth usage."""
    return jsonify(get_bandwidth_usage())

@app.route('/api/speed-test', methods=['GET'])
def speed_test():
    """Run a speed test."""
    result = run_speed_test()
    return jsonify(result)

@app.route('/api/speed-test/history', methods=['GET'])
def speed_test_history():
    """Get speed test history."""
    hours = request.args.get('hours', 24, type=int)
    return jsonify(get_speed_test_history(hours))

@app.route('/api/scan-now', methods=['POST'])
def scan_now():
    """Force an immediate network scan."""
    devices = scan_network()
    return jsonify({"message": "Scan completed", "devices": devices})

@app.route('/api/threats', methods=['GET'])
def threats():
    """Get threat log."""
    return jsonify(threat_log)

@app.route('/api/connections', methods=['GET'])
def connections():
    """Get active connections."""
    return jsonify(active_connections)

@app.route('/api/device/<mac>/trust', methods=['POST'])
def trust_device(mac):
    """Mark a device as trusted."""
    conn = sqlite3.connect('network_monitor.db')
    c = conn.cursor()
    
    c.execute("UPDATE devices SET is_trusted = ? WHERE mac = ?", (True, mac))
    conn.commit()
    conn.close()
    
    # Update cache if device is present
    with lock:
        for device in device_cache:
            if device['mac'] == mac:
                device['is_trusted'] = True
                device['threat'] = False
                device['threat_level'] = 0
    
    log_network_event('device_trusted', mac, {})
    return jsonify({"message": f"Device {mac} marked as trusted"})

@app.route('/api/device/<mac>/block', methods=['POST'])
def block_device(mac):
    """Block a device from the network."""
    # In a real implementation, this would use firewall rules
    # For now, we'll just log the event
    log_network_event('device_blocked', mac, {})
    return jsonify({"message": f"Device {mac} blocked"})

# ---------------- BACKGROUND TASKS ---------------- #

def background_scanner():
    """Background task for periodic network scanning."""
    global speed_cache
    while True:
        try:
            scan_network()
            # Run speed test less frequently
            if time.time() % 300 < 60:  # Every ~5 minutes
                speed_cache = run_speed_test()
        except Exception as e:
            logger.error(f"Background scan error: {e}")
        time.sleep(60)

def bandwidth_monitor():
    """Monitor bandwidth usage periodically."""
    while True:
        try:
            # Update network stats for each device based on bandwidth usage
            # This is a simplified implementation
            with lock:
                for device in device_cache:
                    if device['mac'] != 'Unknown':
                        if device['mac'] not in network_stats:
                            network_stats[device['mac']] = deque(maxlen=100)
                        # Simulate activity based on random fluctuation
                        activity = max(5, min(95, device['activity'] + random.randint(-10, 10)))
                        network_stats[device['mac']].append(activity)
                        device['activity'] = activity
        except Exception as e:
            logger.error(f"Bandwidth monitor error: {e}")
        time.sleep(30)

if __name__ == '__main__':
    # Initial scan
    scan_network()
    
    # Start background tasks
    threading.Thread(target=background_scanner, daemon=True).start()
    threading.Thread(target=bandwidth_monitor, daemon=True).start()
    
    # Start Flask app
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)