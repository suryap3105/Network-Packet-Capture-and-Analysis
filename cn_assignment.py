import os
import time
import matplotlib.pyplot as plt
from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, ARP
from collections import defaultdict

# Dictionary to count packet types over time
packet_counts = defaultdict(lambda: defaultdict(int))
start_time = None

# Function to process packets
def process_packet(packet):
    global start_time
    if start_time is None: #to initialize if the timer has not yet started.
        start_time = time.time()
    
    elapsed_time = round(time.time() - start_time, 1)  # calculates time since start of capture
    
    # Identify protocol type
    if packet.haslayer(TCP):
        protocol = "TCP"
    elif packet.haslayer(UDP):
        protocol = "UDP"
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    elif packet.haslayer(ARP):
        protocol = "ARP"
    elif packet.haslayer(IP):
        protocol = "IP"
    elif packet.haslayer("NBNS"):  # NetBIOS Name Service
        protocol = "NBNS"
    elif packet.haslayer("MDNS"):  # Multicast DNS
        protocol = "MDNS"
    else:
        protocol = "Other"
    
    # Increment the count for this protocol at this time instance
    packet_counts[elapsed_time][protocol] += 1

# Function to capture packets
def capture_packets(interface, duration):
    print(f"Starting packet sniffer on {interface} for {duration} seconds...")
    packets = sniff(iface=interface, timeout=duration, prn=process_packet)
    
    # Save captured packets to a file
    wrpcap("captured_packets.pcap", packets)
    print("Packets saved to captured_packets.pcap")
    
    # Open captured packets in Wireshark
    os.system("wireshark -r captured_packets.pcap &")

# Function to plot the graph
def plot_graph():
    if not packet_counts:
        print("No packets captured, skipping graph generation.")
        return

    plt.figure(figsize=(10, 6))
    
    # Extract unique protocol names
    protocols = {"TCP", "UDP", "ICMP", "ARP", "NBNS", "MDNS", "IP"}
    
    # Plot data for each protocol
    for protocol in protocols:
        times = sorted(packet_counts.keys())
        counts = [packet_counts[t].get(protocol, 0) for t in times]
        plt.plot(times, counts, marker="o", label=protocol)
        
        # Display packet counts as text above points
        for x, y in zip(times, counts):
            if y > 0:
                plt.text(x, y, str(y), fontsize=10, ha="right", va="bottom")

    plt.xlabel("Time (seconds)")
    plt.ylabel("Packet Count")
    plt.title("Packet Types Captured Over Time")
    plt.legend()
    plt.grid(True)
    plt.show()

# Main function
def main():
    interface = input("Enter network interface (e.g., eth0, wlan0, lo): ")
    duration = int(input("Enter capture duration in seconds: "))
    
    capture_packets(interface, duration)
    
    # Plot the graph after execution
    plot_graph()

if __name__ == "__main__":
    main()

