#!/usr/bin/env python3 

import socket
import struct 
import array 
import logging
import argparse
from tcp import TCPPacket

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Make the functions craft the packets ? use them to make the TCPPackets then forward through sockets ? 

#### TODO list ####
# TODO : find out why i'm not receiving SYN+ACK 
# TODO : add cli options to change host ip , dest ip , source port,  destination port 
# TODO : send SYN+ACK 
def syn_pak(src_ip: str,src_p: int,dst_ip: str,dst_p: int) -> TCPPacket:
    """
    Creates a TCPPacket instance which builds the headers for a TCP SYN packet. Generates an ISN.

    Args:
        src_ip (str): IP address of the client
        src_p (int): Client ephemeral port 
        dst_ip (str): IP of the server, or receiving host
        dst_p (str): Port the client will forward the request to. 

    Returns:
        syn_pak (TCPPacket): Instance of TCPPacket with header structure generated, ready for snd
    """
    # Send SYN packet 
    syn_pak = TCPPacket(
        src_ip,
        src_p, # Source port 
        dst_ip,
        dst_p, # Destination port 
        0b000000010  # Send SYN 
    )
    #s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    #s.sendto(syn_pak.build(), (dst, 0)) # Send the packet to server

    logging.info(f"[Client] Sending SYN to {dst}")
    return syn_pak

 #def send_ACK()
    #return 
# Receives ACK from recv() function 
def recv_syn_ack(src_ip: str):
    """
    Receives the SYN+ACK TCP segment sent from server

    Args: 
        src_ip (str): IP address of the sender, AKA the server's IP address 

    Returns:
        Nothing so far...
    """

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    while True:

        raw_data, addr = s.recvfrom(65535) 
        ip_header = raw_data[:20]
        ip_hdr = struct.unpack("!BBHHHBBH4s4s", ip_header)
        protocol = ip_hdr[6] # Protocol number 
        src_ip = socket.inet_ntoa(ip_hdr[8]) # Source IP 
        dest_ip = socket.inet_ntoa(ip_hdr[9]) # Destination IP 

        if protocol == socket.IPPROTO_TCP:
            ### RECEIVE TCP SEGEMENT ### 
            tcp_header = raw_data[20:40] 
            tcp_hdr = struct.unpack("!HHLLBBHHH", tcp_header) 
            tcp_dst_port = tcp_hdr[0]
            tcp_src_port = tcp_hdr[1]
            tcp_ack = tcp_hdr[3]
            tcp_seq = tcp_hdr[4]
            tcp_control_flags = tcp_hdr[5]
            ### RECEIVE SYN+ACK ####
            if src_ip  == "192.168.3.101" and tcp_control_flags == 18:
                logging.info(f"[Client] Received SYN + ACK")
                # ACK packet 
                syn_ack_pak = TCPPacket(
                    dest_ip,
                    20,
                    src_ip,
                    tcp_dst_port,
                    0b000010010 # TODO : change to ACk 
                )
                seq = tcp_ack  
                ack = tcp_seq + 1 # ACK = SERVER_SEQ + 1 
                s.sendto(syn_ack_pak.build(ack=ack, seq=seq),(dst,0))
                logging.info(f"[Client] Sending ACK")

# Function responsible for sending formed packets 
def send_pak():
    return 
# Function that is responsible for all sendto() statments 
def recv_pak():
    return 

if __name__ == '__main__':
    # Parse CLI arguements 
    """
    Arguments : 
        -s, --source-ip (str): IP address of the client
        -p, --source-port (int): Client ephemeral port 
        -D, --dest-ip (str): IP of the server, or receiving host
        -P, --dest-port (int): Port the client will forward the request to. 

    """
    parser = argparse.ArgumentParser(description='Client 3-way Handshake implementation')
    parser.add_argument('-s', '--source-ip', type=str,help='IP address of the client',required=True)
    parser.add_argument('-p', '--source-port', type=int,help='Client ephemeral port ') # Source port can be randomly picked 
    parser.add_argument('-D', '--dest-ip', type=str,help='IP of the server, or receiving host')
    parser.add_argument('-P', '--dest-port', type=int,help='Port the client will forward the request to. ',required=True)
    
    # Variables defined from argparsing 
    args = parser.parse_args()
    src_ip = args.source_ip
    src_port = 20 if not args.source_port else args.source_port
    dest_ip = args.dest_ip
    dest_port = args.dest_port
    


    #send_syn_segment()
    #receive_syn_ack()
    #send_ack()
