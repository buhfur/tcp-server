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

