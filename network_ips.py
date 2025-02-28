from scapy.all import ARP, Ether, srp
import time

def scan_network(target_ip):
    # Create an ARP request to get all devices on the network
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine them into a single packet
    packet = broadcast/arp_request
    # Send the packet on the network and get the response
    result = srp(packet, timeout=3, verbose=False)[0]
    
    # List of all devices (IP and MAC)
    devices = []
    for sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    
    return devices

def get_local_ip():
    # Get the local IP address of the machine
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('8.8.8.8', 80))  # Connect to Google's public DNS server
        local_ip = s.getsockname()[0]
    except Exception as e:
        local_ip = "Unable to fetch IP"
    finally:
        s.close()
    return local_ip

def get_network_range(local_ip):
    # Find out the network range based on the local IP
    subnet = '.'.join(local_ip.split('.')[:3]) + '.0/24'
    return subnet

def log_devices(devices):
    # Store the results in a text file
    with open("network_devices.txt", "a") as file:
        file.write(f"Device Scan at: {time.ctime()}\n")
        if devices:
            for device in devices:
                file.write(f"IP Address: {device['ip']} | MAC Address: {device['mac']}\n")
        else:
            file.write("No devices found.\n")
        file.write("\n" + "-"*50 + "\n")

def main():
    local_ip = get_local_ip()
    print(f"Local IP: {local_ip}")
    
    # Get the network range (e.g., 192.168.1.0/24)
    network_range = get_network_range(local_ip)
    print(f"Scanning Network: {network_range}")

    while True:
        print("\nScanning for devices...")
        devices = scan_network(network_range)
        log_devices(devices)  # Log the devices in the text file
        
        # Wait for 30 minutes (1800 seconds) before scanning again
        time.sleep(1800)

if __name__ == "__main__":
    main()
