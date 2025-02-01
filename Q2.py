from scapy.all import *
import re

packets = rdpcap("captured_output.pcap")

ip_address = None
for packet in packets:
    if packet.haslayer(Raw):
        data = packet[Raw].load.decode(errors="ignore")
        if "< my ip address = >" in data:
            ip_address = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", data)[0]
            print(f"Q1: Found IP address: {ip_address}")
            break

if ip_address:
    packet_count = sum(1 for packet in packets if packet.haslayer(IP) and (packet[IP].src == ip_address or packet[IP].dst == ip_address))
    print(f"Q2: Total packets with IP {ip_address}: {packet_count}")

laptop = None
for packet in packets:
    if packet.haslayer(Raw):
        data = packet[Raw].load.decode(errors="ignore")
        if "laptop name" in data:
            laptop = data.split("laptop name")[-1].strip()
            print(f"Q3a: Laptop name detected: {laptop}")
            break

if laptop:
    for packet in packets:
        if packet.haslayer(Raw):
            data = packet[Raw].load.decode(errors="ignore")
            if "laptop name" in data:
                checksum = packet[TCP].chksum
                print(f"Q3b: TCP checksum: {checksum}")
                break

order_successful = 0
for packet in packets:
    if packet.haslayer(Raw):
        data = packet[Raw].load.decode(errors="ignore")
        if "Order successful" in data:
            order_successful += 1

print(f"Q4: Packets with 'Order successful': {order_successful}")
