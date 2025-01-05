#!/usr/bin/env python3 

# Simple TCP echo server using high level functions 
import os 
import socket 
import sys 

HOST = '192.168.3.104'
PORT = 65535 # same as server 

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((HOST,PORT))
        
    print(f"Connected to server at {HOST}:{PORT}")
    while True:
        message = input("Enter message to send or 'exit' to quit :>")
        if message.lower() == 'exit':
            break
        client.sendall(message.encode('utf-8'))
        data = client.recv(1024)
        print(f"Received from server: {data.decode('utf-8')}")
