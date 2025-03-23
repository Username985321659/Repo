#How It Works
#Packet Sniffing:
#The script uses Scapy's sniff() to capture UDP packets on port 53. Each packet is passed to process_packet().

#DNS Query Analysis:
#In process_packet(), if a packet contains a DNS query (i.e., qr == 0), it extracts the query name and logs it.

#Heuristic Checks:
#The function is_tunneling() applies multiple heuristics:

#Label Count: Flags queries with more than five labels.

#Label Length: Checks for labels nearing the 63-character limit.

#Total Query Length: Flags unusually long queries.

#Entropy: Computes the Shannon entropy of the first label; high entropy may indicate encoded data.

#Pattern Matching: Looks for base32/base64-like patterns in the first label.

#Alerting:
#If any heuristic indicates suspicious behavior, a warning is logged.

#This basic program is designed to illustrate the principles described in the GIAC article (available at GIAC paper). In a production environment, you might refine the heuristics, add additional logging, and integrate with alerting systems.

#Feel free to adjust the thresholds and heuristics as needed for your network's normal DNS traffic patterns.


import math
import re
import logging
from scapy.all import *

# Configure logging for alerts
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# Heuristic thresholds based on typical DNS tunneling behavior
LABEL_COUNT_THRESHOLD = 5       # More than 5 labels is suspicious
LABEL_LENGTH_THRESHOLD = 63     # Maximum length for a DNS label is 63 characters (suspicious if near this)
TOTAL_LENGTH_THRESHOLD = 253    # Maximum overall domain length is 253 characters
ENTROPY_THRESHOLD = 4.0         # Entropy threshold for the first label

def calculate_entropy(s):
    """
    Calculate the Shannon entropy of a string.
    A higher entropy indicates a more random distribution of characters.
    """
    if not s:
        return 0
    probabilities = [float(s.count(c)) / len(s) for c in set(s)]
    entropy = -sum([p * math.log(p, 2) for p in probabilities])
    return entropy

def is_tunneling(qname):
    """
    Analyze a DNS query name for signs of tunneling based on several heuristics.
    
    Returns True if the query is suspicious.
    """
    # Remove trailing dot if present and split into labels
    if qname.endswith('.'):
        qname = qname[:-1]
    labels = qname.split('.')
    
    # Heuristic 1: Excessive number of labels
    if len(labels) > LABEL_COUNT_THRESHOLD:
        logging.debug("Suspicious: High label count (%d)", len(labels))
        return True

    # Heuristic 2: Unusually long labels
    for label in labels:
        if len(label) > int(LABEL_LENGTH_THRESHOLD * 0.8):  # near max label length
            logging.debug("Suspicious: Label '%s' is unusually long", label)
            return True

    # Heuristic 3: Overall query length is near the maximum allowed
    if len(qname) > int(TOTAL_LENGTH_THRESHOLD * 0.8):
        logging.debug("Suspicious: Overall query length is high (%d characters)", len(qname))
        return True

    # Heuristic 4: High entropy in the first label
    if labels:
        first_label_entropy = calculate_entropy(labels[0])
        if first_label_entropy > ENTROPY_THRESHOLD:
            logging.debug("Suspicious: High entropy in first label (%f)", first_label_entropy)
            return True

    # Heuristic 5: Check if the first label appears to be encoded (base32/base64)
    if re.fullmatch(r'[A-Za-z0-9+/=]+', labels[0]) and len(labels[0]) > 20:
        logging.debug("Suspicious: First label appears encoded: %s", labels[0])
        return True

    return False

def process_packet(packet):
    """
    Process each captured DNS packet and log suspicious queries.
    """
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:  # Ensure it is a DNS query
        dns_layer = packet.getlayer(DNS)
        try:
            qname = dns_layer.qd.qname.decode("utf-8")
        except Exception as e:
            logging.error("Error decoding qname: %s", e)
            return

        logging.info("DNS Query: %s", qname)
        if is_tunneling(qname):
            logging.warning("Potential DNS tunneling detected for query: %s", qname)

def main():
    """
    Start the DNS tunneling detection by sniffing UDP traffic on port 53.
    """
    logging.info("Starting DNS Tunneling Detection...")
    sniff(filter="udp port 53", prn=process_packet, store=0)

if __name__ == "__main__":
    main()
