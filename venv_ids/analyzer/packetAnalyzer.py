import pandas as pd
import os

# Define packet_analyzer to receive specific packet data
def packet_analyzer(src_ip, dst_ip, protocol, src_port, dst_port, ttl, packet_id):
    columns = ["src_ip", "dst_ip", "protocol", "src_port", "dst_port", "ttl", "id"]
    
    # Prepare the packet data
    packet_data = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "ttl": ttl,
        "id": packet_id
    }
    
    # Check if the CSV file  exists
    if not os.path.exists("packet_log.csv"):
        # If the file does not exist, create a new DataFrame and write the header
        packet_log = pd.DataFrame(columns=columns)
        packet_log.to_csv("packet_log.csv", mode='w', index=False, header=True)
    
    # Append the packet data to the CSV file (without the header)
    packet_log = pd.DataFrame([packet_data], columns=columns)
    packet_log.to_csv("packet_log.csv", mode='a', index=False, header=False)



# import pandas as pd

# # Define packet_analyzer to receive specific packet data
# def packet_analyzer(src_ip, dst_ip, protocol, src_port, dst_port, ttl, packet_id):
#     # Create a DataFrame with a single row containing the new packet data
#     packet_data = pd.DataFrame([{
#         "src_ip": src_ip,
#         "dst_ip": dst_ip,
#         "protocol": protocol,
#         "src_port": src_port,
#         "dst_port": dst_port,
#         "ttl": ttl,
#         "Id": packet_id  # Make sure this matches the column name in your CSV file
#     }])

#     # Append the data to the CSV file without overwriting existing data
#     packet_data.to_csv("packet_log.csv", mode='a', index=False, header=False)

   








# #  print(f"{protocol} Packet: {ip_src}:{port_src} ----> {ip_dst}:{port_dst}, ID: {ip_packet_number}, TTL: {ip_ttl}, Version: {ip_version}")

# # capture.py
# # from scapy.all import sniff
# # from packet_analysis import PacketAnalyzer

# # analyzer = PacketAnalyzer()

# # def packet_callback(packet):
# #     analyzer.analyze_packet(packet)

# # print("Starting packet capture... (Press Ctrl+C to stop)")
# # try:
# #     sniff(filter="tcp or udp or (udp port 53) or icmp", prn=packet_callback, store=0, count=100, iface="en0")
# # except KeyboardInterrupt:
# #     print("Stopping the network monitor.")
# #     analyzer.log_to_csv()  # Log results to CSV when capture stops
