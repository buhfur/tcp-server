#!/usr/bin/env python3 

# simple TCP server using raw sockets 
# Handles retrans, ack handling, basic sliding window proto 
# Used for other projects as a test server to poke and prod at 

# Created based on the RFC 793 standard 
import socket 
import struct 
import logging 

# TODO: Only handle the tcp handshake process, respond with ACK + SYN 
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.IPPROTO_TCP)

def recv_tcp_seg():
    rcv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    rcv_sock.bind(("0.0.0.0", 443)) # Listen on any interface 

    while True:

        ### RECEIVE IP PACKET ###
        raw_data, addr = recv_socket.recvfrom(65535) 
        # IP header is the first 20 bytes 
        ip_header = raw_data[:20]
        ip_hdr = struct.unpack("!BBHHHBBH4s4s", ip_header)
        protocol = ip_hdr[6] # Protocol number 
        src_ip = socket.inet_ntoa(ip_hdr[8]) # Source IP 
        dest_ip = socket.inet_ntoa(ip_hdr[9]) # Destination IP 

        # Check if packet is TCP segment 
        if protocol == socket.IPPROTO_TCP:
            ### RECEIVE TCP SEGEMENT ### 
            # Unpack TCP header ( next 20 bytes after IP header )
            tcp_header = raw_data[20:40]
            tcp_hdr = struct.unpack("!HHLLBBHHH", tcp_header) # Change middle L's to I's if problems arise with transmission 
            # First 16 ( 2 bytes )bits is the source port 
            tcp_dst_port = tcp_hdr[0]
            tcp_src_port = tcp_hdr[1]
            # Check if TCP segment has SYN control bit  
            #logging.info(f"{src_ip} / {tcp_dst_port}")
            if src_ip  == "162.159.134.234":
                logging.info(f"Control fields : {tcp_hdr[5]}")
                logging.info(f"{tcp_hdr}")

            if tcp_hdr[5] == 2:
                # TODO : Find out why I can't capture SYN packets ? 
                logging.info(f"SYN packet detected : {tcp_hdr}\n{tcp_hdr[5]}")

            #logging.info(f"tcp_header: {tcp_hdr}\nSource Port: {tcp_hdr[1]}\nDestination Port : {tcp_hdr[0]}\n")

            #else:
                #logging.info(f"tcp_header: {tcp_hdr}\nSource Port: {tcp_hdr[1]}\nDestination Port : {tcp_hdr[0]}\n")




if __name__ == '__main__':
    recv_tcp_seg()
