#!/usr/bin/env python3 

import socket
import time
import queue 
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
        return s
    except PermissionError:
        logging.info("[ERROR] Could not create socket, root priveleges are required")
        sys.exit(1)
    except Exception as e:
        logging.info(f"socket creation failed : {e}")
        sys.exit(1)


# Client sends SYN packet 
def snd_pak(handshake_queue: queue.Queue, sock: socket.socket, packet: TCPPacket,  target_ip:str, interval=5):
    """
    Sends packets based on an interval through a raw socket, takes TCPPacket, socket , str as arguemnt 

    Args:
        sock (socket.socket): Socket object initialized through init_socket()
        packet (TCPPacket): TCPPacket instance, ISN is generated and passed to TCPPacket.build(seq=ISN)
        target_ip (str): IP address of the receiving host 
        interval (int): default interval , determines rate packets are sent

    Returns:
        None
    """
    ### GENERATE TCP PACKET HERE ###
    

    while True:
        try:
            if handshake_queue.empty():  # If queue is empty , SYN has not been sent
                # Send SYN 
                # TODO: Generate random sequence number for seq  
                ISN = random.randint(1,1000)
                sock.sendto(packet.build(seq=ISN), (target_ip, 65535)) # Set SEQ to ISN
                logging.info(f"[Client] Sending SYN packet to {target_ip}")
                handshake_queue.put(2) # Adds control flag to queue to signal first step in handshake 
            elif handshake_queue.get() == 18:
                # Send ACK 
                # TODO : get ACK and SEQ from TCPPacket()   


        except Exception as e: 
            logging.info(f"[ERROR] Failed to send packet : {e}")

        time.sleep(interval)

def recv_pak(sock: socket.socket, server_ip:str):
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
            ip_header = data[:20]
            ip_hdr = struct.unpack("!BBHHHBBH4s4s", ip_header)
            sender_ip = socket.inet_ntoa(ip_hdr[8]) # IP of the sender, should be the server's IP 
            # Disect TCP segment and verify if SYN + ACK 
            tcp_header = data[20:40] # Grab TCP segement 
            tcp_hdr = struct.unpack("!HHLLBBHHH", tcp_header)
            # Check if SYN + ACK was from server IP 
            if sender_ip == server_ip : 
                # Conditional should be based on result retrieved from queue 
                if tcp_hdr[5] == 18:
                    logging.info(f"[Client] Received SYN+ACK from {server_ip}")
                    # Add SYN+ACK packet to shared queue 
                    handshake_queue.put(tcp_hdr[5])
                    # Disect IP packet and use for values 
                    #ack_pak = TCPPacket()

                elif tcp_hdr[5] == 16: 
                    
                    logging.info(f"[Client] Received ACK from {sender_ip}")

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
    send_thread = threading.Thread(target=snd_pak, args=(handshake_queue,init_sock, syn_pak, target_ip), daemon=True)
    recv_thread = threading.Thread(target=send_packets, args=(handshake_queue,init_sock, target_ip), daemon=True)

    # Start both threads 
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


