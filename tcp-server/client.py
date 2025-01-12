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
        logging.info(
            "[ERROR] Could not create socket, root priveleges are required\n")
        sys.exit(1)
    except Exception as e:
        logging.info(f"socket creation failed : {e}\n")
        sys.exit(1)


def snd_pak(sock: socket.socket, handshake_queue: queue.Queue, source_ip: str,
            source_port: int, target_ip: str, target_port: int, interval=5):
    """
    Sends packets based on an interval through a raw socket, takes initial fields for TCP segment and sends SYN packet if the shared queue object is empty

    Args:
        handshake_queue (queue.Queue): Shared object which stores received packets from target_ip
        sock (socket.socket): Socket object initialized through init_socket()
        interval (int): default interval , determines rate packets are sent

    Returns:
        None
    """

    while True:
        try:
            try:
                # Analyze which packet was recently received in the queue
                packet = handshake_queue.get_nowait()  # Grabs TCPPacket() instance from queue
                # Check if recent packet was SYN+ACK
                if packet.flags == 18:  # Send ACK in response to SYN+ACK
                    ACK = packet.seq + 1  # Increments the sequence number and assigns to ACK
                    SEQ = packet.ack + 1  # Sequence number is the value of the ACK received
                    ack_pak = packet  # Modify existing instance of TCPPacket() in shared queue
                    ack_pak.ack = ACK
                    ack_pak.seq = SEQ
                    ack_pak.flags = 0b000010000  # Set ACK for control flags
                    # Sends ACK packet to server
                    sock.sendto(ack_pak.build(), (ack_pak.src_host, ack_pak.dst_port))
                    # Get heades of packet being sent to server
                    logging.info(f"[Client] ACK packet headers:\n\t{ack_pak.get_pak()}\n")
                    logging.info(f"[Client] Sending ACK to server\n")

                elif packet.flags == 16:  # Start data transfer after server receives ACK
                    logging.info(f"[Client] handshake complete !")
            except queue.Empty:
                # Send SYN packet
                ISN_c = random.randint(1, 1000) # Generate Client Sequence number 
                syn_pak = TCPPacket(source_ip,
                                    source_port,
                                    target_ip,
                                    target_port,
                                    ISN_c,
                                    0,
                                    0b000000010  # SYN control flag
                                    )
                # Generate random sequence number for seq
                # Get headers of packet being sent to server
                logging.info(
                    f"[Client] SYN Packet headers:\n\t{syn_pak.get_pak()}\n")
                sock.sendto(
                    syn_pak.build(),
                    (syn_pak.dst_host,
                     syn_pak.dst_port))  # Send SYN packet
                logging.info(
                    f"[Client] Sending SYN packet to {syn_pak.dst_host}\n")

        except Exception as e:
            logging.info(f"[ERROR] Failed to send packet : {e}")

        time.sleep(interval)


def recv_pak(sock: socket.socket, handshake_queue: queue.Queue,
             server_ip: str):
    """
    Receives packets from raw socket returned by init_socket()

    Args:
        sock (socket.socket): Socket object initialized through init_socket()
        server_ip (str): IP address of the host who sent the packet
        data_queue (queue.Queue): Shared object which stores control flags ( SOON TO CHANGE  )

    Returns:
        None
    """

    while True:
        try:
            # Listen for incoming packets , 65535 is the max size the IP packet
            # can be
            data, addr = sock.recvfrom(65535)
            # Convert byte string into TCPPacket instance
            packet = TCPPacket.build_pak(data)
            if packet.src_host == server_ip:  # Check if SYN + ACK was from server IP
                if packet.flags == 18 and packet.dst_port == 65535: # Check if SYN+ACK was received
                    logging.info(
                        f"[Client] Adding SYN+ACK packet from {server_ip} to queue\nPacket info:\n\t{packet.get_pak()}\n")
                    handshake_queue.put_nowait(packet)  # Add packet to queue

        except Exception as e:
            print(f'[ERROR]: {e}\n')


def main(source_ip: str, source_port: int, target_ip: str, target_port: int):

    # TODO : read/write packets from the queue rather than the individual
    # control flags
    handshake_queue = queue.Queue()

    init_sock = init_socket()  # initialize socket to send / recv on
    send_thread = threading.Thread(
        target=snd_pak,
        args=(
            init_sock,
            handshake_queue,
            source_ip,
            source_port,
            target_ip,
            target_port),
        daemon=True)
    recv_thread = threading.Thread(
        target=recv_pak,
        args=(
            init_sock,
            handshake_queue,
            target_ip),
        daemon=True)
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
    parser = argparse.ArgumentParser(
        description='Client 3-way Handshake implementation')
    parser.add_argument('-s', '--source-ip', type=str,
                        help='IP address of the client')
    parser.add_argument(
        '-p',
        '--source-port',
        type=int,
        help='Client ephemeral port ')  # Source port can be randomly picked
    parser.add_argument(
        '-D',
        '--dest-ip',
        type=str,
        help='IP of the server, or receiving host')
    parser.add_argument(
        '-P',
        '--dest-port',
        type=int,
        help='Port the client will forward the request to. ')

    # Variables defined from argparsing
    args = parser.parse_args()
    src_ip = "192.168.3.104" if not args.source_ip else args.source_ip
    # Sets default source port to 20
    src_port = 20 if not args.source_port else args.source_port
    dest_ip = "192.168.3.101" if not args.dest_ip else args.dest_ip
    dest_port = 65535 if not args.dest_port else args.dest_port

    main(src_ip, src_port, dest_ip, dest_port)
