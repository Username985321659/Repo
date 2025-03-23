import math
import re
from scapy.all import *

def calculate_entropy(s):
    """
    Calculate the Shannon entropy of a string.
    Higher entropy may indicate randomness or encoding.
    """
    if not s:
        return 0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    entropy = - sum([p * math.log(p, 2) for p in prob])
    return entropy

def check_for_tunneling(qname):
    """
    Heuristically determine if the DNS query name might be used for tunneling.
    
    Checks include:
      - Too many subdomains.
      - Any label is unusually long.
      - High entropy in the first label.
    """
    labels = qname.split('.')
    
    # Check if there are too many subdomains.
    if len(labels) > 5:
        return True

    # Check if any label is unusually long (common in DNS tunneling to pack data).
    for label in labels:
        if len(label) > 40:
            return True

    # Check entropy of the first label.
    if labels:
        entropy = calculate_entropy(labels[0])
        # A threshold entropy value; adjust as needed.
        if entropy > 4.0:
            return True

    return False

def process_packet(packet):
    """
    Process each captured packet and inspect DNS queries for tunneling patterns.
    """
    # Ensure the packet has a DNS layer and is a query (qr == 0).
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        dns_layer = packet.getlayer(DNS)
        qname = dns_layer.qd.qname.decode().rstrip('.')
        print(f"DNS Query for: {qname}")
        if check_for_tunneling(qname):
            print("Potential DNS tunneling detected!")
            # Here you can add logging, alerts, or further processing.

def main():
    """
    Start the DNS tunneling detector by sniffing UDP traffic on port 53.
    """
    print("Starting DNS Tunneling Detector...")
    # Sniff UDP traffic on port 53 (DNS). Do not store packets in memory.
    sniff(filter="udp port 53", prn=process_packet, store=0)

if __name__ == "__main__":
    main()
