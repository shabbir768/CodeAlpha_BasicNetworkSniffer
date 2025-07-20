from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        print("\n[+] Packet Captured")
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")

        if proto == 6 and packet.haslayer(TCP):  # TCP
            print("Protocol       : TCP")
            payload = bytes(packet[TCP].payload).decode(errors="ignore")
            print(f"Payload        : {payload[:100]}")
        elif proto == 17 and packet.haslayer(UDP):  # UDP
            print("Protocol       : UDP")
            payload = bytes(packet[UDP].payload).decode(errors="ignore")
            print(f"Payload        : {payload[:100]}")
        elif proto == 1 and packet.haslayer(ICMP):  # ICMP
            print("Protocol       : ICMP")
        else:
            print("Protocol       : Other")

print("=== Starting Packet Sniffer ===")
print("Press CTRL+C to stop.\n")
sniff(filter="ip", prn=process_packet, store=False)
