import matplotlib.pyplot as plt
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import numpy as np

# Variables for storing results
dataTransferred = 0
packetSizes = []
totalPackets = 0
capture_duration = 200  # capture duration in seconds

# Variables for Q2 (Unique Source-Destination Pairs)
unique_pairs = set()  # Set to store unique (source, destination) pairs (IP:port)
source_flows = defaultdict(int)  # Dictionary to store source IP and the count of flows
destination_flows = defaultdict(int)  # Dictionary to store destination IP and the count of flows

# Variables for tracking max packet details
max_packet = None  # Will hold the packet with the maximum size
max_packet_size = 0  # The maximum size of the packet

# Packet processing function to analyze each packet
def process_packet(pkt):
    global dataTransferred, packetSizes, totalPackets, max_packet, max_packet_size

    packet_size = len(pkt)  # Size of the captured packet
    dataTransferred += packet_size
    packetSizes.append(packet_size)
    totalPackets += 1

    # Update maximum packet size and details if this packet is larger
    if packet_size > max_packet_size:
        max_packet_size = packet_size
        max_packet = pkt  # Store the packet with the maximum size

    # Check if the packet has IP layer and transport layer (TCP or UDP)
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        
        # Check if it's a TCP or UDP packet for source-destination port info
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        else:
            return  # If it's not TCP or UDP, ignore the packet
        
        # Unique source-destination pair (IP:port)
        src_dst_pair = (ip_src, src_port, ip_dst, dst_port)
        unique_pairs.add(src_dst_pair)

        # Count flows for the source and destination IP addresses
        source_flows[ip_src] += 1
        destination_flows[ip_dst] += 1

    # Print or update stats periodically if you want to see it live
    if totalPackets % 100 == 0:
        avgSize = dataTransferred / totalPackets
        print(f"Total amount of data transferred: {dataTransferred} bytes")
        print(f"Total number of packets transferred: {totalPackets}")
        print(f"Average packet size: {avgSize:.2f} bytes")
        print(f"Minimum packet size: {min(packetSizes)} bytes")
        print(f"Maximum packet size: {max(packetSizes)} bytes")

# Function to start capturing packets live for a specified duration
def live_capture(interface="enp0s3"):
    print(f"Starting live capture on interface {interface}...")
    sniff(iface=interface, prn=process_packet, store=False, timeout=capture_duration)

# Function to display and save results to a text file
def save_results_to_file(filename="results.txt"):
    avgSize = dataTransferred / totalPackets if totalPackets > 0 else 0
    
    with open(filename, 'w') as f:
        # Part 1: Data and Packet Metrics
        f.write("Part 1: Data and Packet Metrics\n")
        f.write(f"Total amount of data transferred: {dataTransferred} bytes\n")
        f.write(f"Total number of packets transferred: {totalPackets}\n")
        f.write(f"Minimum packet size: {min(packetSizes)} bytes\n")
        f.write(f"Maximum packet size: {max(packetSizes)} bytes\n")
        f.write(f"Average packet size: {avgSize:.2f} bytes\n")
        
        # Distribution of packet sizes (histogram)
        f.write("\nDistribution of packet sizes (histogram of packet sizes):\n")
        f.write(str(np.histogram(packetSizes, bins=50)) + "\n")
        
        # Part 2: Unique Source-Destination Pairs
        f.write("\nPart 2: Unique Source-Destination Pairs (source IP:port, destination IP:port)\n")
        for pair in unique_pairs:
            f.write(f"Source: {pair[0]}:{pair[1]}, Destination: {pair[2]}:{pair[3]}\n")
        
        # Part 3: Source and Destination Flows
        f.write("\nPart 3: Source IP address and their flow counts:\n")
        for ip, count in source_flows.items():
            f.write(f"{ip}: {count} flows\n")
        
        f.write("\nPart 3: Destination IP address and their flow counts:\n")
        for ip, count in destination_flows.items():
            f.write(f"{ip}: {count} flows\n")

        # Part 4: Max Packet Details
        f.write("\nPart 4: Maximum Packet Details\n")
        if max_packet:
            f.write(f"Maximum Packet Size: {max_packet_size} bytes\n")
            f.write(f"Source IP: {max_packet[IP].src}, Destination IP: {max_packet[IP].dst}\n")
            if TCP in max_packet:
                f.write(f"Source Port: {max_packet[TCP].sport}, Destination Port: {max_packet[TCP].dport}\n")
            elif UDP in max_packet:
                f.write(f"Source Port: {max_packet[UDP].sport}, Destination Port: {max_packet[UDP].dport}\n")
            f.write(f"Packet Raw Data: {max_packet.summary()}\n")

        f.write("\n")

    print(f"Results saved to {filename}")

# Run the live capture and then save the results
live_capture()  # Start capturing packets for the specified duration
save_results_to_file("results.txt")  # After capture ends, save the results to a file
