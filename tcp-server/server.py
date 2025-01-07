#!/usr/bin/env python3 

# simple TCP server using raw sockets 
# Handles retrans, ack handling, basic sliding window proto 
# Used for other projects as a test server to poke and prod at 

# Created based on the RFC 793 standard 
import socket 
import struct 
import logging 
import argparse
import random
from tcp import TCPPacket

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

#### TODO LIST ####  
# TODO: Only handle the tcp handshake process, respond with ACK + SYN 
# TODO : add cli options to change host ip , dest ip , source port,  destination port 
 

def recv_tcp_seg():
    rcv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    rcv_sock.bind(("0.0.0.0", 0)) # Listen on any interface 

    server_ip = "192.168.3.104" 
    client_ip = "192.168.3.101"
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
            server_ack = 0
            server_seq = 0
            #### SEND SYN + ACK ####
            if src_ip  == client_ip: 
                # TODO : Generate Seq num , set ACK to ISN + 1 received from client 
                if tcp_control_flags == 2:
                    syn_ack_pak = TCPPacket(
                        dest_ip,
                        20,
                        src_ip,
                        tcp_dst_port,
                        0b000010010
                    )
                    logging.info(f"[Server] Received SYN, sending SYN-ACK")
                    server_seq = random.randint(1,1000) # randomly gen seq num
                    server_ack = tcp_ack + 1 # ACK = ISN + 1 
                    rcv_sock.sendto(syn_ack_pak.build(ack=server_ack, seq=server_seq),(src_ip,0))
                    logging.info(f"[Server] Sent SYN + ACK  to {src_ip} from {dest_ip}")
                elif src_ip == client_ip and tcp_control_flags == 16 and tcp_ack == server_ack + 1 :
                    # TODO : Send ACK 
                    logging.info(f"[Server] Server ACK = {server_ack} SEQ = {server_seq}")
                    logging.info(f"[Server] Received ACK from {src_ip}")

            








if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Server 3-way Handshake implementation')
    parser.add_argument('-s', '--source-ip', type=str,help='IP address of the server',required=True)
    parser.add_argument('-p', '--source-port', type=int,help='Client ephemeral port ') # Source port can be randomly picked 
    parser.add_argument('-D', '--dest-ip', type=str,help='IP of the server, or receiving host')
    parser.add_argument('-P', '--dest-port', type=int,help='Port the client will forward the request to. ',required=True)
    
    # Variables defined from argparsing 
    args = parser.parse_args()
    src_ip = args.source_ip
    src_port = 20 if not args.source_port else args.source_port
    dest_ip = args.dest_ip
    dest_port = args.dest_port
    print(f"src_port: {src_port}")
    recv_tcp_seg()
