import sys
import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR
from analyzer import packetAnalyzer


##########################################################################
# sniff: The main function to capture packets.
# IP: Represents the IP layer.
# TCP: Represents TCP packets.
# UDP: Represents UDP packets.
# ICMP: Represents ICMP packets (used for ping, etc.).
# DNS: Represents DNS packets.
# DNSQR: Represents DNS query records (useful for analyzing DNS requests).
# HTTPRequest: Represents HTTP requests.
##########################################################################

# function to process each captured packet
def packet_callback(packet):
    timestamp = datetime.datetime.now().strftime("%c")
    # Check if the packet has an IP layer (to filter out non-IP packets)
    if IP in packet:
        ip_packet_number = packet[IP].id # unique number that identifies the packet and its place in the overall information
        ip_src = packet[IP].src    # The IP address of the device that sent the packet 
        ip_dst = packet[IP].dst    # The IP address of the device that will receive the packet 
        ip_protocol = packet[IP].proto #Type of packet being transferred, such as an email, video, or web page 
        ip_ttl = packet[IP].ttl #How long routers should forward the packet before dropping it 
        ip_version = packet[IP].version #The version of the internet protocol being used, such as IPv4 or IPv6 
        ip_packet_length = len(packet[IP]) #The size of the packet 
        
        # Check if the packet contains TCP or UDP
        if TCP in packet:
            protocol = "TCP"
            port_src = packet[TCP].sport  # Source port for TCP
            port_dst = packet[TCP].dport  # Destination port for TCP
            flags = packet[TCP].flags  # TCP flags (SYN, ACK, etc.)
        elif UDP in packet:
            protocol = "UDP"
            port_src = packet[UDP].sport  # Source port for UDP
            port_dst = packet[UDP].dport  # Destination port for UDP

            if DNS in packet:
                if packet[DNS].qr == 0:  # DNS query
                    print(f"DNS Query from {ip_src} to {ip_dst}: {packet[DNSQR].qname.decode()}")
                elif packet[DNS].qr == 1:  # DNS response
                    print(f"DNS Response from {ip_src} to {ip_dst}")
        
            elif ICMP in packet:
                print(f"ICMP Packet: {ip_src} ----> {ip_dst}")

        else:
            protocol = "Other"
            port_src = "N/A"
            port_dst = "N/A"
        
        print(f"{protocol} Packet: {ip_src}:{port_src} ----> {ip_dst}:{port_dst}, ID: {ip_packet_number}, TTL: {ip_ttl}, Version: {ip_version}, timestamp: {timestamp}")
        packetAnalyzer.packet_analyzer(ip_src, ip_dst, ip_protocol, port_src, port_dst, ip_ttl, ip_packet_number, timestamp)

    else:
        print(f"{packet} Packet : Non-IP Packet")
try:
    # Run sniff in an infinite loop
    print("Starting packet capture... (Press Ctrl+C to stop)")
    # sniff(filter="tcp or udp or (udp port 53) or icmp", prn=packet_callback, store=0, count = 50) # Normal Mode: Captures only packets that are directly sent to or from my device.
    sniff(filter="tcp or udp or (udp port 53) or icmp", prn=packet_callback, store=0, count = 50, iface="en0") # Promiscuous Mode: Captures all packets on the network segment, not just those addressed to my device.

except KeyboardInterrupt:
    print("Stopping the network monitor.")

   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
    #figure out the actual data being sent

# import subprocess
# command = "echo my2Jahs@ws | sudo -S python first_scapy_script.py"
# subprocess.run(command, shell=True)


# Source IP address: The IP address of the device that sent the packet 
# Destination IP address: The IP address of the device that will receive the packet 
# ////////////////////////////////////////////////


# '''
# Breakdown of the Script:
# sniff function:  Used to capture packets. You can specify various filters like interface, count, or timeout if needed. Here, Im capturing on the default interface and passing each packet to the packet_callback function.

# packet_callback function: processes each packet. checks if the packet has an IP layer, if so, it extracts the source and destination IP addresses. It further checks for TCP and UDP layers to extract source and destination ports.

# Output:  prints each packet's source and destination IP addresses and, if available, the protocol (TCP/UDP) and port numbers.


# ////////////////////////////////////////////////
# Example Output:
# Starting packet capture... (Press Ctrl+C to stop)
# TCP Packet: 192.168.1.100:54871 -> 93.184.216.34:80
# UDP Packet: 192.168.1.100:57543 -> 8.8.8.8:53
# TCP Packet: 192.168.1.100:54872 -> 93.184.216.34:80
# TCP Packet: 192.168.1.100:54873 -> 93.184.216.34:443

# ////////////////////////////////////////////////
# Notes:
# Permissions: To run this script you'll need root privileges (using sudo) because packet sniffing typically requires elevated privileges.
# Filters: You can modify sniff() with filters, for example:
    # Capture only TCP packets: sniff(prn=packet_callback, filter="tcp", store=0)
    # Capture only traffic on a specific interface: sniff(iface="eth0", prn=packet_callback, store=0)
# '''