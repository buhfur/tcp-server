#!/usr/bin/env python3 
import socket
# Simple TCP echo server using higher level functions 
# This script should be interpreted and converted 
# to a server which does not use the higher level functions 
# and is implemented from scratch 


HOST = '127.0.0.1'
PORT = 65535

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST,PORT)) # Binds socket src and src ip ? 
    server.listen() # puts socket in LISTEN state 
    print(f"Server is listening on {HOST}:{PORT}")
    conn , addr = server.accept() # socket put in ACCEPT state 
    with conn:
        print(f"Connected by {addr}")
        while True:
            data = conn.recv(1024) # Receive data in 1024 bytes at a time
            if not data: 
                break
            print(f"Received: {data.decode('utf-8')}") # Decode data to readable format 
            conn.sendall(data) # Send data to client socket 

