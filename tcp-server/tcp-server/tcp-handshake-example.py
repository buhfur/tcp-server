#!/usr/bin/env python3
from scapy.all import sniff, TCP, IP

# Callback function to process packets


def process_packet(packet):
    if TCP in packet:
        tcp_layer = packet[TCP]
        # SYN flag (Initial handshake step 1)
        if tcp_layer.flags == "S":
            print(
                f"SYN detected: {packet[IP].src}:{tcp_layer.sport} -> {packet[IP].dst}:{tcp_layer.dport}")
            # SYN-ACK flag (Handshake step 2)
        elif tcp_layer.flags == "SA":
            print(
                f"SYN-ACK detected: {packet[IP].src}:{tcp_layer.sport} -> {packet[IP].dst}:{tcp_layer.dport}")
            # ACK flag (Handshake step 3)
        elif tcp_layer.flags == "A":
            print(
                f"ACK detected: {packet[IP].src}:{tcp_layer.sport} -> {packet[IP].dst}:{tcp_layer.dport}")

            # Start sniffing on a specific interface
            print("Capturing TCP handshake packets... Press Ctrl+C to stop.")
            sniff(filter="tcp", prn=process_packet)

# Sniff for TCP packets to identify real handshakes happening


# does this return a packet I can pass to the function ?
print("Capturing TCP handshake packets, press Ctrl+C to stop.")
sniff(filter="tcp",prn=process_packet) # uses process_packet as callback function 



# Put function here or in lambda function ?
