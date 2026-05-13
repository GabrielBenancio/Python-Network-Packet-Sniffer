from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS

# Packet counters
tcp_count = 0
udp_count = 0
icmp_count = 0
http_count = 0
https_count = 0
dns_count = 0


def analyze_packet(packet):

    global tcp_count
    global udp_count
    global icmp_count
    global http_count
    global https_count
    global dns_count

    # IP
    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        print("\n" + "=" * 50)
        print(f"[+] Source IP: {src_ip}")
        print(f"[+] Destination IP: {dst_ip}")

        # TCP
        if packet.haslayer(TCP):

            tcp_count += 1

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            print("[+] Protocol: TCP")
            print(f"[+] Source Port: {src_port}")
            print(f"[+] Destination Port: {dst_port}")

            # HTTP
            if src_port == 80 or dst_port == 80:
                http_count += 1
                print("[+] Application Protocol: HTTP")

            # HTTPS
            elif src_port == 443 or dst_port == 443:
                https_count += 1
                print("[+] Application Protocol: HTTPS")

        # UDP
        elif packet.haslayer(UDP):

            udp_count += 1

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            print("[+] Protocol: UDP")
            print(f"[+] Source Port: {src_port}")
            print(f"[+] Destination Port: {dst_port}")

            # DNS Detection
            if packet.haslayer(DNS):
                dns_count += 1
                print("[+] Application Protocol: DNS")

        # ICMP
        elif packet.haslayer(ICMP):

            icmp_count += 1

            print("[+] Protocol: ICMP")

        # Packet Counts by Protocol
        print("\n[*] Packet Statistics")
        print(f"TCP Packets: {tcp_count}")
        print(f"UDP Packets: {udp_count}")
        print(f"ICMP Packets: {icmp_count}")
        print(f"HTTP Packets: {http_count}")
        print(f"HTTPS Packets: {https_count}")
        print(f"DNS Packets: {dns_count}")


print("[*] Starting Advanced Packet Sniffer...")

sniff(prn=analyze_packet, count=25)

print("\n[*] Packet Sniffing Complete")