from scapy.all import *
import matplotlib.pyplot as plt
from collections import defaultdict

# Load the PCAP file
packets = rdpcap("captured_output.pcap")

# Initialize variables
total_bytes = 0
packet_sizes = []
src_dst_pairs = set()
flows_src = defaultdict(int)
flows_dst = defaultdict(int)
traffic_data = defaultdict(int)

# Process each packet
for pkt in packets:
    packet_size = len(pkt)  # Get packet size
    total_bytes += packet_size
    packet_sizes.append(packet_size)
    
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        
        src_dst_pairs.add((src_ip, src_port, dst_ip, dst_port))
        flows_src[src_ip] += 1
        flows_dst[dst_ip] += 1
        traffic_data[(src_ip, dst_ip)] += packet_size

# Metrics Calculation
total_packets = len(packets)
min_size = min(packet_sizes) if packet_sizes else 0
max_size = max(packet_sizes) if packet_sizes else 0
avg_size = total_bytes / total_packets if total_packets > 0 else 0

# File writing
output_filename = "ans.txt"

try:
    with open(output_filename, "w") as f:
        f.write(f"Total Data Transferred: {total_bytes} bytes\n")
        f.write(f"Total Packets Transferred: {total_packets}\n")
        f.write(f"Min Packet Size: {min_size}, Max Packet Size: {max_size}, Avg Packet Size: {avg_size:.2f}\n\n")

        f.write("Unique Source-Destination Pairs:\n")
        for pair in src_dst_pairs:
            f.write(f"{pair}\n")

        f.write("\nSource IP Flows:\n")
        for ip, count in flows_src.items():
            f.write(f"{ip}: {count} flows\n")

        f.write("\nDestination IP Flows:\n")
        for ip, count in flows_dst.items():
            f.write(f"{ip}: {count} flows\n")

        # Find the largest data transfer
        max_transfer = max(traffic_data.items(), key=lambda x: x[1], default=None)
        if max_transfer:
            f.write("\nLargest Data Transfer:\n")
            f.write(f"Source: {max_transfer[0][0]}, Destination: {max_transfer[0][1]}, Bytes Transferred: {max_transfer[1]}\n")
    
    print(f"Output successfully written to {output_filename}")

except Exception as e:
    print(f"Error writing to file: {e}")

# Plot packet size distribution and save it as an image
plt.hist(packet_sizes, bins=20, edgecolor="black")
plt.xlabel("Packet Size (bytes)")
plt.ylabel("Frequency")
plt.title("Packet Size Distribution")
plt.savefig("packet_distribution.png")  # Save the plot
print("Histogram saved as packet_distribution.png")
