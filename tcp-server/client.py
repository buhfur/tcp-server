#!/usr/bin/env python3 

import socket
import struct 
import array 
from tcp import TCPPacket



if __name__ == '__main__':
    dst = '192.168.3.101'
    
    # Send SYN packet 
    syn_pak = TCPPacket(
        '192.168.3.104',
        20, # Source port 
        dst,
        65535, # Destination port 
        0b000000010  # Merry Christmas!
    )


    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.sendto(syn_pak.build(), (dst, 0))
    s.bind(("0.0.0.0", 0))

    while True:

        # TODO : send SYN+ACK 
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
            if src_ip  == "192.168.3.101" and tcp_control_flags == 18:
                logging.info(f"[Server] Received SYN, sending SYN-ACK")
                logging.info(f"[Server] Client ACK = {tcp_ack}")
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
                logging.info(f"[Client] Received SYN + ACK, Sending ACK")



