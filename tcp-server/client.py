#!/usr/bin/env python3 

# TCP client 

# Original source code taken from source below :
# https://www.kytta.dev/blog/tcp-packets-from-scratch-in-python-3/
import socket 
import struct 
import random

'''
Connection estab 
C->S : SYN , ISN generated and sent by client 
S->C : SYN-ACK
C->S : ACK

Data Transfer:
C->S : Data 
S->C : ACK

Connection Term:
C->S : FIN
S->C : ACK
S->C : FIN
C->S : ACK 

Control flag representation reference 

ACK : 0x010
SYN : 0x002
PSH : 

Control flag in binary : 
    1   2   3   4   5   6   7   8   9  10  11  12
    0   0   0   0   0   0   0   0   0   0   0   0
    |   |   |   |   |   |   |   |   |   |   |   | 
    +---+---+   V   V   V   V   V   V   V   V   V
        |     Nonce CWR ECN Urg Ack Psh Rst Syn Fin 
        V
      Reserved

Control bit Binary -> int 
SYN: 
    000000000010 = 2
SYN+ACK : 
    000000010010 = 18

ACK : 
    000000010000 = 16 



'''
import struct 

# Checksum : 16 bit ones complement of the ones complement sum of all 16 bit words in the header and text 
def checksum(packet: bytes) -> int:
    if len(packet) % 2 != 0: # 
        packet += b'\0'

    res = sum(array.array("H", packet)) # Sum of all 16bit words ? 
    res = (res >> 16) + (res & 0xffff)
    return (~res) & 0xffff


class TCPPacket:
    def __init__(self,
                src_host: str,
                src_port: int, 
                dst_host: str,
                dst_port: int,
                flags: int = 0): 
        self.src_host = src_host 
        self.src_port = src_port 
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.flags = flags

        # Pseudo header ? 
    
    # construct fields into byte sequence  
    def build(self) -> bytes:

        packet = struct.pack(
            # ! = network byte order , H = unsigned short ( 2 bytes ) , L = unsigned long ( 4 bytes ) , B = Unsigned Char ( 1 byte ) , single byte flags
            '!HHIIBBHHH', # Format string, defines binary structure, data types , byte order ( host / network )
            src_p,     # Host source port , 16 bits, 2 bytes 
            dst_p,     # Destination port,  16 bits, 2 bytes 
            seq,       # SEQ , increments with every SYN or FIN control bit set 
            ack,       # ACK , acknowledgement, 32 bits , 4 bytes 
            5 << 4,    # Binary shift for offset 
            flags,     # Control flags , FIN , SYN , PSH , RST , 6 bits [URG,ACK,PSH,RST,SYN,FIN]  <-- in this order of bits from left to right 
            8192,      # Window size , sliding window , 
            0,         # Checksum 
            0,         # Urgent pointer 
        )

        # Construct pseudo header 
        pseudo_hdr = struct.pack(
                '!4s4sHH', # Format string : 4s = 4 char[] , H = unsigned short
                socket.inet_aton(self.src_host), # Src address 
                socket.inet_aton(self.dst_host), # destination address 
                socket.IPPROTO_TCP,              # PTCL 
                len(packet)                      # TCP length, includes length of data sent  

                )

        # Compute checksum and add to packet 
        csum = checksum(pseudo_hdr + packet)
        packet = packet[:16] + struct.pack('H',checksum) + packet[18:]

        return packet


# SEND SYN  

syn_pak = TCPPacket(
        '192.168.3.104',                      # Source IP 
        random.randint(1026,65535),           # Source Port 
        '192.168.3.104',                      # Destination IP 
        65535                                 # Destination Port 
        )

dst = "192.168.3.104"
s = socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.IPPROTO_TCP)
s.sendto(syn_pak.build(), (dst, 0))

# RECV SYN + ACK = SEQ + 1 

# SEND ACK 



