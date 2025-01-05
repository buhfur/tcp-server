#!/usr/bin/env python3 

# Original source code taken from source below :
# https://www.kytta.dev/blog/tcp-packets-from-scratch-in-python-3/
import socket 
import struct 
import random
import array
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

Handshake steps : 
1. Client generates Initial Sequence  num , sends to server , Syn bit set
2. Server responds with random generated Sequence num , Ack is set to ISN + 1 and sent to client. Syn and Ack bit set 
3. Client sets Sequence num to value of ACK from server , ACK is set to Seuqence value from Server + 1. 
4. Data is sent using same Sequence Number and ACK value from end of handshake 
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
def chksum(packet: bytes) -> int:
    if len(packet) % 2 != 0:
        packet += b'\0'

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return (~res) & 0xffff


class TCPPacket:
    def __init__(self,
                 src_host:  str,
                 src_port:  int,
                 dst_host:  str,
                 dst_port:  int,
                 flags:     int = 0):
        self.src_host = src_host
        self.src_port = src_port
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.flags = flags

    # TODO generate unique seq number 
    def build(self) -> bytes:
        packet = struct.pack(
            '!HHIIBBHHH',
            self.src_port,  # Source Port
            self.dst_port,  # Destination Port
            0,              # Sequence Number
            0,              # Acknoledgement Number
            5 << 4,         # Data Offset
            self.flags,     # Flags
            8192,           # Window
            0,              # Checksum (initial value)
            0               # Urgent pointer
        )

        pseudo_hdr = struct.pack(
            '!4s4sHH',
            socket.inet_aton(self.src_host),    # Source Address
            socket.inet_aton(self.dst_host),    # Destination Address
            socket.IPPROTO_TCP,                 # PTCL
            len(packet)                         # TCP Length
        )

        checksum = chksum(pseudo_hdr + packet)

        packet = packet[:16] + struct.pack('H', checksum) + packet[18:]

        return packet


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

