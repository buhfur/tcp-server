#!/usr/bin/env python3 
# TCP handshake client 
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
# TODO : find out why i'm not receiving SYN+ACK 
# TODO : add cli options to change host ip , dest ip , source port,  destination port 
# TODO : send SYN+ACK 

# NOTE: server and client use port 65535 for destination port , source port is 20 
# NOTE: Base code was generated using GPT to assist with re-write 

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
        logging.info(f"[Client] Created socket successfully\n")
        return s
    except PermissionError:
        logging.info("[ERROR] Could not create socket, root priveleges are required")
        sys.exit(1)
    except Exception as e:
        logging.info(f"socket creation failed : {e}")
        sys.exit(1)

def snd_pak(sock: socket.socket, packet: TCPPacket,interval=5,handshake_queue=handshake_queue):
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
            if handshake_queue.empty():  # If queue is empty , SYN has not been sent
                ISN_c = random.randint(1,1000) # Generate random sequence number for seq  
                syn_packet = packet
                syn_packet.seq = ISN_c # Set sequence number to ISN
                sock.sendto(syn_packet.build(), (syn_packet.dst_host, syn_packet.dst_port)) # Send SYN  
                logging.info(f"[Client] Sending SYN packet to {syn_packet.dst_host}")
                handshake_queue.put(2) # Adds control flag to queue to signal first step in handshake 

            elif handshake_queue.get() == 18: # Send ACK in response to SYN+ACK
                ACK = packet.seq + 1 # Increments the sequence number and assigns to ACK 
                SEQ = packet.ack + 1  # Sequence number is the value of the ACK received
                ack_pak = packet
                ack_pak.ack = ACK
                ack_pak.seq = SEQ
                ack_pak.flags = 0b000010000 # Set ACK for control flags
                sock.sendto(ack_pak.build(), (ack_pak.src_host, ack_pak.dst_port)) # Sends ACK packet to server
                logging.info(f"[Client] Sending ACK to server")
                handshake_queue.put(ack_pak.flags)

            elif handshake_queue.get() == 16: # Start data transfer after server receives ACK 
                logging.info(f"[Client] handshake complete !")


        except Exception as e: 
            logging.info(f"[ERROR] Failed to send packet : {e}")

        time.sleep(interval)

def recv_pak(sock: socket.socket, server_ip:str,handshake_queue=handshake_queue):
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
            packet = TCPPacket.build_pak(data) # Convert byte string into TCPPacket instance 
            if packet.src_host == server_ip : # Check if SYN + ACK was from server IP 
                if packet.flags == 18: # Checks if packet has SYN+ACK control flag
                    logging.info(f"[Client] Received SYN+ACK from {server_ip}\n")
                    handshake_queue.put(packet.flags) # Add SYN+ACK flag to shared queue 
                    logging.info(f"[QUEUE] Current queue : {handshake_queue.get()}\n")
                    send_pak(sock, packet) # Send packet to send function to send ACK
                    
        except Exception as e:
            print(f'[ERROR]: {e}')

def main(source_ip: str,source_port: int, target_ip: str, target_port: int):
    syn_pak = TCPPacket(source_ip, 
                        source_port,
                        target_ip,
                        target_port,
                        0b000000010 # SYN control flag 
                        )

    init_sock = init_socket() # initialize socket to send / recv on 
    send_thread = threading.Thread(target=snd_pak, args=(init_sock, syn_pak), daemon=True)
    recv_thread = threading.Thread(target=recv_pak, args=(init_sock, target_ip), daemon=True)
    send_thread.start()
    recv_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("[Client] Keyboard interrupt detected. Closing socket")
    finally:
        init_sock.close()
        logging.info("[Client] Closed socket successfully")

            
if __name__ == '__main__':
    # Parse CLI arguements 
    """
    Arguments( Optional ) : 
        -s, --source-ip (str): IP address of the client
        -D, --dest-ip (str): IP of the server, or receiving host
        -P, --dest-port (int): Port the client will forward the request to. 

    """
    parser = argparse.ArgumentParser(description='Client 3-way Handshake implementation')
    parser.add_argument('-s', '--source-ip', type=str,help='IP address of the client')
    parser.add_argument('-p', '--source-port', type=int,help='Client ephemeral port ') # Source port can be randomly picked 
    parser.add_argument('-D', '--dest-ip', type=str,help='IP of the server, or receiving host')
    parser.add_argument('-P', '--dest-port', type=int,help='Port the client will forward the request to. ')
    
    # Variables defined from argparsing 
    args = parser.parse_args()
    src_ip = "192.168.3.104" if not args.source_ip else args.source_ip
    src_port = 20 if not args.source_port else args.source_port # Sets default source port to 20 
    dest_ip = "192.168.3.101" if not args.dest_ip else args.dest_ip 
    dest_port = 65535 if not args.dest_port else args.dest_port
    
    
    main(src_ip, src_port, dest_ip, dest_port)


