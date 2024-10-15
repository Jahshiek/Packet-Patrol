
from scapy.all import sniff, IP, TCP, UDP

# Define a function to process each captured packet
def packet_callback(packet):
    # Check if the packet has an IP layer (to filter out non-IP packets)
    if IP in packet:
        ip_packet_number = packet[IP].id # unique number that identifies the packet and its place in the overall information
        ip_src = packet[IP].src    # The IP address of the device that sent the packet 
        ip_dst = packet[IP].dst    # The IP address of the device that will receive the packet 
        ip_protocol = packet[IP].proto #Type of packet being transferred, such as an email, video, or web page 
        ip_ttl = packet[IP].ttl #How long routers should forward the packet before dropping it 
        ip_version = packet[IP].version #The version of the internet protocol being used, such as IPv4 or IPv6 
        ip_packet_length = packet[IP].ihl #The size of the packet 
        
        # Check if the packet contains TCP or UDP
        if TCP in packet:
            protocol = "TCP"
            port_src = packet[TCP].sport  # Source port for TCP
            port_dst = packet[TCP].dport  # Destination port for TCP
        elif UDP in packet:
            protocol = "UDP"
            port_src = packet[UDP].sport  # Source port for UDP
            port_dst = packet[UDP].dport  # Destination port for UDP
        else:
            protocol = "Other"
            port_src = "N/A"
            port_dst = "N/A"
        
        # print(f"{protocol} Packet: {ip_src}:{port_src} -> {ip_dst}:{port_dst}")
        print(f" Non-IP Packet TEST.... {ip_packet_number}, {ip_protocol}:{protocol}, {ip_ttl}, {ip_version}, {ip_packet_length}")
    else:
        print(f"Non-IP Packet {packet}")

# Capture packets on the default network interface (Ctrl+C to stop)
print("Starting packet capture... (Press Ctrl+C to stop)")
sniff(prn=packet_callback, store=0)  # store=0 prevents saving packets in memory


# Source IP address: The IP address of the device that sent the packet 
# Destination IP address: The IP address of the device that will receive the packet 



'''
Breakdown of the Script:
sniff function:  Used to capture packets. You can specify various filters like interface, count, or timeout if needed. Here, Im capturing on the default interface and passing each packet to the packet_callback function.

packet_callback function: processes each packet. checks if the packet has an IP layer, if so, it extracts the source and destination IP addresses. It further checks for TCP and UDP layers to extract source and destination ports.

Output:  prints each packet's source and destination IP addresses and, if available, the protocol (TCP/UDP) and port numbers.


////////////////////////////////////////////////
Example Output:
plaintext
Copy code
Starting packet capture... (Press Ctrl+C to stop)
TCP Packet: 192.168.1.100:54871 -> 93.184.216.34:80
UDP Packet: 192.168.1.100:57543 -> 8.8.8.8:53
TCP Packet: 192.168.1.100:54872 -> 93.184.216.34:80
TCP Packet: 192.168.1.100:54873 -> 93.184.216.34:443

////////////////////////////////////////////////
Notes:
Permissions: You will need to run this script with root privileges (e.g., using sudo) because packet sniffing typically requires elevated privileges.
Filters: You can modify sniff() with filters, for example:
Capture only TCP packets: sniff(prn=packet_callback, filter="tcp", store=0)
Capture only traffic on a specific interface: sniff(iface="eth0", prn=packet_callback, store=0)
This basic script is a great starting point for capturing and analyzing network traffic. From here, you can expand to save packets, apply more detailed filtering, or analyze specific protocols like HTTP or DNS.
'''