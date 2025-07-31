from scapy.all import rdpcap

def read_pcap(file):
    packets = rdpcap(file)
    for pkt in packets:
        if pkt.haslayer("IP"):
            ip_layer = pkt["IP"]
            print(f"From {ip_layer.src} to {ip_layer.dst} - Proto: {ip_layer.proto}")
        else:
            print(pkt.summary())

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <pcap_file>")
        sys.exit(1)
    read_pcap(sys.argv[1])
