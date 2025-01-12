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
                 seq: int = 0, # Default values for seq and ack 
                 ack: int = 0,
                 flags:     int = 0):
        self.src_host = src_host
        self.src_port = src_port
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.seq = seq
        self.ack = ack 
        self.flags = flags

    """
    Function that converts a TCPPacket instance into a byte string ready for transmission
    """
    def build(self) -> bytes:
        packet = struct.pack(
            '!HHIIBBHHH',
            self.src_port,  # Source Port
            self.dst_port,  # Destination Port
            self.seq,              # Sequence Number
            self.ack,              # Acknoledgement Number
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

    """
    Conveinience function that takes a byte object as input and returns an instance of the TCPPacket class

    Args:
        packet (bytes) : byte object received from socket

    Returns:
        TCPPacket()
    """
    @staticmethod 
    def build_pak(packet: bytes):
        ip_header = packet[:20]
        ip_hdr = struct.unpack("!BBHHHBBH4s4s", ip_header)
        protocol = ip_hdr[6] # Protocol number 
        src_ip = socket.inet_ntoa(ip_hdr[8]) # Source IP 
        dest_ip = socket.inet_ntoa(ip_hdr[9]) # Destination IP 

        if protocol == socket.IPPROTO_TCP:

            tcp_header = packet[20:40] 
            tcp_hdr = struct.unpack("!HHLLBBHHH", tcp_header) 

            # Return TCPPacket instance 
            return TCPPacket( 
                    src_ip,
                    tcp_hdr[1],
                    dest_ip,
                    tcp_hdr[0],
                    tcp_hdr[4],
                    tcp_hdr[3],
                    tcp_hdr[5]
            )

    """
    Conveinience function that prints out headers of TCP segment , useful for debugging

    Arguments:
        None

    Returns:
        packet_info (str): Formatted string of TCP segments headers 
    """

    def get_pak(self) -> str:
        packet_info = f"\n\t[Source IP] : {self.src_host}\n\t[Source Port]: {self.src_port}\n\t[Destination IP]: {self.dst_host}\n\t[Destination Port]: {self.dst_port}\n\t[Sequence Number]: {self.seq}\n\t[Acknowledgement]: {self.ack}\n\t[Flags]: {self.flags}\n\n"
        return packet_info


if __name__ == '__main__':
   
    # Testing purposes 
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    while True:
        data, addr = s.recvfrom(65535)
        packet = TCPPacket.build_pak(data)
        print(packet.get_pak()) 
        #print(f"[Source IP] : {packet.src_host}\n[Source Port]: {packet.src_port}\n[Destination IP]: {packet.dst_host}\n[Destination Port]: {packet.dst_port}\n[Sequence Number]: {packet.seq}\n[Acknowledgement]: {packet.ack}\n[Flags]: {packet.flags}\n\n")
        
        
    
