#!/usr/bin/env python3 

# simple TCP server using raw sockets 
# Handles retrans, ack handling, basic sliding window proto 
# Used for other projects as a test server to poke and prod at 

# Created based on the RFC 793 standard 
import socket 
import struct 
import logging 
import random
from tcp import TCPPacket

# TODO: Only handle the tcp handshake process, respond with ACK + SYN 
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

#recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.IPPROTO_TCP)

def recv_tcp_seg():
    rcv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    rcv_sock.bind(("0.0.0.0", 0)) # Listen on any interface 

    while True:

        # TODO : send SYN+ACK 
        ### RECEIVE IP PACKET ###
        raw_data, addr = rcv_sock.recvfrom(65535) 
        # IP header is the first 20 bytes 
        ip_header = raw_data[:20]
        ip_hdr = struct.unpack("!BBHHHBBH4s4s", ip_header)
        protocol = ip_hdr[6] # Protocol number 
        src_ip = socket.inet_ntoa(ip_hdr[8]) # Source IP 
        dest_ip = socket.inet_ntoa(ip_hdr[9]) # Destination IP 

        # Check if packet is TCP segment 
        if protocol == socket.IPPROTO_TCP:
            ### RECEIVE TCP SEGEMENT ### 
            tcp_header = raw_data[20:40] # Unpack TCP header ( next 20 bytes after IP header )
            tcp_hdr = struct.unpack("!HHLLBBHHH", tcp_header) # Change middle L's to I's if problems arise with transmission 
            # First 16 ( 2 bytes )bits is the source port 
            tcp_dst_port = tcp_hdr[0]
            tcp_src_port = tcp_hdr[1]
            tcp_ack = tcp_hdr[3]
            tcp_control_flags = tcp_hdr[5]
            # Check if TCP segment has SYN control bit  
            if src_ip  == "192.168.3.104" and tcp_control_flags == 2:
                # TODO : Generate Seq num , set ACK to ISN + 1 received from client 
                logging.info(f"[Server] Received SYN, sending SYN-ACK")
                logging.info(f"[Server] Client ACK = {tcp_ack}")
                # Generate SYN + ACK packet 
                syn_ack_pak = TCPPacket(
                    dest_ip,
                    20,
                    src_ip,
                    tcp_dst_port,
                    0b000010010
                )
                seq = random.randint(1,1000) # randomly gen seq num
                ack = tcp_ack + 1 # ACK = ISN + 1 
                rcv_sock.sendto(syn_ack_pak.build(ack=ack, seq=seq),(src_ip,0))


            if tcp_hdr[5] == 2:
                logging.info(f"SYN packet detected : {tcp_hdr}\n{tcp_hdr[5]}")






if __name__ == '__main__':
    recv_tcp_seg()
