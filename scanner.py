from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
import socket

# Initialize MacLookup once, outside the scan function
mac_lookup = MacLookup()
try:
    mac_lookup.update_vendors()  # downloads/updates OUI DB once
except Exception:
    pass  # ignore errors if offline or already updated

def scan_network(target_ip="192.168.1.1/24"):
    """
    Scans the local network subnet for devices,
    returning list of devices with IP, MAC, Vendor, Hostname.
    """
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send packet and receive responses
    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []

    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc

        # Try to get hostname via reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = "Unknown"

        # Lookup vendor from MAC address
        try:
            vendor = mac_lookup.lookup(mac)
        except Exception:
            vendor = "Unknown"

        devices.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "connected": True
        })

    return devices

if __name__ == "__main__":
    devices = scan_network()
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device['vendor']}, Hostname: {device['hostname']}")
