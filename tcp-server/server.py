#!/usr/bin/env python3 
# TCP server 

import socket
import time
import struct 
import sys
import threading 
import array 
import logging
import argparse
from tcp import TCPPacket

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


#### TODO list ####
# TODO : find out why i'm not receiving SYN+ACK 
# TODO : add cli options to change host ip , dest ip , source port,  destination port 
# TODO : send SYN+ACK 
# TODO : use queue as shared object between both threads 

# NOTE: server and client use port 65535 for destination port , source port is 20 
# NOTE: Base code was generated using GPT to assist with re-write 


def init_socket() -> socket.socket:
    """
    Creates the initial socket used for sending and receiving data 

    Args:
        None
    Returns:
        s (socket.scoket): Socket object 
    """
    try: 
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        return s
    except PermissionError:
        print("[ERROR] Could not create socket, root priveleges are required")
        sys.exit(1)
    except Exception as e:
        print(f"socket creation failed : {e}")
        sys.exit(1)


# Server sends SYN packet 
def snd_pak(sock: socket.socket, packet: TCPPacket,  target_ip:str, interval=5):
    """
    Sends packets based on an interval through a raw socket, takes TCPPacket, socket , str as arguemnt 

    Args:
        sock (socket.socket): Socket object initialized through init_socket()
        packet (TCPPacket): Manually formed tcp packet to be sent , not limited to specific cflags
        target_ip (str): IP address of the receiving host 
        interval (int): default interval , determines rate packets are sent

    Returns:
        None
    """
    ### GENERATE TCP PACKET HERE ###
    

    while True:
        try:
            # Conditional based on queue , change seq & ack in packet as necessary 
            
            sock.sendto(packet, (target_ip, 65535))
            print(f"[Server] Sending SYN packet to {target_ip}")

        except Exception as e: 
            print(f"[ERROR] Failed to send packet : {e}")

        time.sleep(interval)

def recv_pak(sock: socket.socket, client_ip:str):
    """
    Receives packets from raw socket returned by init_socket()

    Args:
        sock (socket.socket): Socket object initialized through init_socket()
        packet (TCPPacket): Manually formed tcp packet to be sent , not limited to specific cflags
        client_ip (str): IP address of the host who sent the packet 

    Returns:
        None
    """

    while True:
        try:
            data, addr = sock.recvfrom(65535)
            # Disect IP header 
            ip_header = data[:20]
            ip_hdr = struct.unpack("!BBHHHBBH4s4s", ip_header)
            sender_ip = socket.inet_ntoa(ip_hdr[8]) # IP of the sender, should be the server's IP 
            # Disect TCP segment and verify if SYN + ACK 
            tcp_header = data[20:40] # Grab TCP segement 
            tcp_hdr = struct.unpack("!HHLLBBHHH", tcp_header)
            # Check if SYN was from server IP 
            if sender_ip == client_ip : 
                if tcp_hdr[5] == 2:
                    print(f"[Server] Received SYN from {client_ip}")
                    # TODO: Construct TCPPacket with ACK 
                    #ack_pak = TCPPacket()

                elif tcp_hdr[5] == 

def main(source_ip: str,source_port: int, target_ip: str, target_port: int):

    # TODO: Construct first SYN packet here
    syn_pak = TCPPacket(source_ip,
                        source_port,
                        target_ip,
                        target_port,
                        0b000000010
                        )

    init_sock = init_socket()

    # Threading for send/recv 
    send_thread = threading.Thread(target=snd_pak, args=(init_sock, syn_pak.build(), target_ip), daemon=True)
    recv_thread = threading.Thread(target=send_packets, args=(init_sock, target_ip), daemon=True)

    # Start both threads 
    send_thread.start()
    recv_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[Server] Keyboard interrupt detected. Closing socket")
    finally:
        init_sock.close()
        print("[Server] Closed socket successfully")

            
if __name__ == '__main__':
    # Parse CLI arguements 
    """
    Arguments( Optional ) : 
        -s, --source-ip (str): IP address of the client
        -D, --dest-ip (str): IP of the server, or receiving host
        -P, --dest-port (int): Port the client will forward the request to. 

    """
    parser = argparse.ArgumentParser(description='Server 3-way Handshake implementation')
    parser.add_argument('-s', '--source-ip', type=str,help='IP address of the client')
    parser.add_argument('-p', '--source-port', type=int,help='Server ephemeral port ') # Source port can be randomly picked 
    parser.add_argument('-D', '--dest-ip', type=str,help='IP of the server, or receiving host')
    parser.add_argument('-P', '--dest-port', type=int,help='Port the client will forward the request to. ')
    
    # Variables defined from argparsing 
    args = parser.parse_args()
    src_ip = "192.168.3.101" if not args.source_ip else args.source_ip
    src_port = 20 if not args.source_port else args.source_port # Sets default source port to 20 
    dest_ip = "192.168.3.104" if not args.dest_ip else args.dest_ip 
    dest_port = 65535 if not args.dest_port else args.dest_port
    
    main(src_ip, src_port, dest_ip, dest_port)


