from scapy.all import rdpcap, TCP
import re
import socket

SUCCESS_MESSAGE = "Order successful"  # Message to search for

# Function to convert bytes to human-readable IP address format
def inet_to_str(inet: bytes) -> str:
    return socket.inet_ntoa(inet)

def process_pcap(pcap_file: str) -> None:
    ip_addresses = set()
    laptop_name = None
    ip_address_of_interest = None
    ip_address_count = 0
    successful_order_count = 0
    tcp_checksum = None

    try:
        # Read packets from pcap file
        packets = rdpcap(pcap_file)
        
        for packet in packets:
            if packet.haslayer(TCP):
                tcp_payload = bytes(packet[TCP].payload)
                src_ip = inet_to_str(packet[packet.ip].src)
                dst_ip = inet_to_str(packet[packet.ip].dst)

                # Q1: Look for the message that contains your IP address
                payload_str = tcp_payload.decode(errors='ignore')
                match = re.search(r'< my ip address = >\s*(\d+\.\d+\.\d+\.\d+)', payload_str)
                if match:
                    ip_address_of_interest = match.group(1)
                    print(f"Q1. Found IP address: {ip_address_of_interest}")

                # Q2: Count packets with that IP address (both source and destination)
                if ip_address_of_interest:
                    if src_ip == ip_address_of_interest or dst_ip == ip_address_of_interest:
                        ip_address_count += 1

                # Q3: Search for laptop name and TCP checksum
                if "laptop name" in payload_str.lower() and laptop_name is None:
                    match_laptop = re.search(r'laptop name\s*=\s*(\S+)', payload_str)
                    if match_laptop:
                        laptop_name = match_laptop.group(1)
                        tcp_checksum = packet[TCP].chksum
                        print(f"Q3a. Laptop name: {laptop_name}")
                        print(f"Q3b. TCP checksum: {tcp_checksum}")

                # Q4: Count packets with "Order successful" in the message
                if SUCCESS_MESSAGE in payload_str:
                    successful_order_count += 1

        # Final results
        print("\nAnalysis Results:")
        print(f"Q2. Number of packets with IP address {ip_address_of_interest}: {ip_address_count}")
        if laptop_name:
            print(f"Q3. Laptop name found in packet: {laptop_name}")
            print(f"Q3b. TCP checksum of the packet with laptop name: {tcp_checksum}")
        print(f"Q4. Number of packets containing 'Order successful': {successful_order_count}")

    except Exception as e:
        print(f"Error processing pcap file: {e}")

if __name__ == "__main__":
    # Provide the pcap file path here
    pcap_file = "2.pcap"  # Replace with your actual pcap file
    process_pcap(pcap_file)
