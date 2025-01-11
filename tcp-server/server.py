#!/usr/bin/env python3 
# TCP handshake server 
import socket
import time
import queue 
import struct 
import sys
import threading 
import array 
import logging
import argparse
import random
from tcp import TCPPacket

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


#### TODO list ####


# TODO : read/write packets from the queue rather than the individual control flags 

handshake_queue = queue.Queue()

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
        logging.info("[ERROR] Could not create socket, root priveleges are required")
        sys.exit(1)
    except Exception as e:
        logging.info(f"socket creation failed : {e}")
        sys.exit(1)

def snd_pak(sock: socket.socket, packet: TCPPacket = None,interval=5,handshake_queue=handshake_queue):
    """
    Sends packets based on an interval through a raw socket, takes TCPPacket, socket , str as arguemnt 

    Args:
        handshake_queue (queue.Queue): Shared object which tracks state of the handshake
        sock (socket.socket): Socket object initialized through init_socket()
        packet (TCPPacket): TCPPacket instance, ISN is generated and passed to TCPPacket.build(seq=ISN)
        interval (int): default interval , determines rate packets are sent

    Returns:
        None
    """
    
    while True:
        try:
            if handshake_queue.empty():
                logging.info("Waiting for SYN packet")
            if handshake_queue.get_nowait() == 2:  # Send SYN + ACK 
                ISN_s = random.randint(1,1000) # Generate random sequence number for seq  
                syn_ack_pak = packet
                syn_ack_pak.seq = ISN_s # Set sequence number to ISN
                syn_ack_pak.ack = syn_ack_pak.seq + 1  # Increment ISN(c) and set as ACK 
                syn_ack_pak.flags = 0b000010010 # Set control flag to SYN + ACK 
                sock.sendto(syn_packet.build(), (syn_ack_packet.src_host, syn_ack_packet.dst_port)) # Send SYN+ACK packet 
                logging.info(f"[Server] Sending SYN+ACK packet to {syn_packet.src_host}")
                handshake_queue.put_nowait(syn_ack_pak.flags) # Adds control flag to queue to signal SYN+ACK has been sent


        except Exception as e: 
            print(e)
            logging.info(f"[ERROR] Failed to send packet : {e}")

        time.sleep(interval)

def recv_pak(sock: socket.socket, client_ip: str, handshake_queue=handshake_queue):
    """
    Receives packets from raw socket returned by init_socket()

    Args:
        sock (socket.socket): Socket object initialized through init_socket()
        server_ip (str): IP address of the host who sent the packet 

    Returns:
        None
    """

    while True:
        try:
            data, addr = sock.recvfrom(65535)
            # Disect IP header 
            packet = TCPPacket.build_pak(data)
            # Check if SYN + ACK was from server IP 
            if packet.dst_host == client_ip : 
                # Checks if packet has SYN control flag
                if packet.flags == 2:
                    logging.info(f"[Server] Received SYN from {client_ip}\n")
                    # Add SYN+ACK flag to shared queue 
                    handshake_queue.put_nowait(packet.flags)
                    logging.info(f"[QUEUE] Current queue : {handshake_queue.get_nowait()()}\n")
                    # Send packet to send function to send ACK
                    handshake_queue.put_nowait(2)
                    send_pak(sock, packet=packet)

                elif packet.flags == 16: 
                    logging.info(f"[Server] Received ACK from {packet.src_host}\n")
                    handshake_queue.put_nowait(16)

                    #send_pak(sock,packet=packet)

        except Exception as e:
            print(f'[ERROR]: {e}')

def main(source_ip: str,source_port: int, target_ip: str, target_port: int):

    init_sock = init_socket() # initialize socket to send / recv on 

    # Threading for send/recv 
    recv_thread = threading.Thread(target=recv_pak, args=(init_sock, target_ip), daemon=True)
    send_thread = threading.Thread(target=snd_pak, args=(init_sock,), daemon=True)

    # Start both threads 
    send_thread.start()
    recv_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("[Server] Keyboard interrupt detected. Closing socket")
    finally:
        init_sock.close()
        logging.info("[Server] Closed socket successfully")

            
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


