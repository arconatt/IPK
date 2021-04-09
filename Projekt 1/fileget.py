#!/usr/bin/env python3

"""
 Name: fileget.py
 Caption: Project 1 of IPK 
 Brief: Implementation of client for trivial distributed file system
 Author: Natália Marková <xmarko20@stud.fit.vutbr.cz>
 Date: 31.03.2021 
"""

import os
import socket 
import re
import string
import sys
import signal
import ipaddress

global NAMESERVER
global IP_ADDRESS
global PORT
global SURL
global SERVER_NAME
global PROTOCOL
global PATH
global FILE

"""Function to check and parse arguments
"""
def CheckArguments():
    
    global NAMESERVER
    global IP_ADDRESS
    global PORT
    global SURL
    global SERVER_NAME
    global PROTOCOL
    global PATH
    global FILE

    if len(sys.argv) != 5:
        sys.exit("Invalid arguments!")
    else:
        for x in range (len(sys.argv)):
            if (x == 1 or x == 3) and (sys.argv[x] == '-n'):
                NAMESERVER = sys.argv[x+1]
                NAMESERVER = NAMESERVER.split(":")
                try:
                    IP_ADDRESS = ipaddress.ip_address(NAMESERVER[0])
                except ValueError:
                    sys.exit("ERR invalid ip address")

                PORT = int(NAMESERVER[1])
            elif (x == 1 or x == 3) and (sys.argv[x] == '-f'):
                SURL = sys.argv[x+1]
                SURL = SURL.split("/", 2)
                PROTOCOL = SURL[0]

                #check validity of protocol, only fsp acceptable
                if PROTOCOL != "fsp:":
                    sys.exit("ERR Wrong Protocol")

                PATH = SURL[2]
                full_path = PATH.split("/", 1)
                SERVER_NAME = full_path[0]
                if (re.search('/', full_path[1]) != None):
                    FILE = "./" + full_path[1]
                else:
                    FILE = full_path[len(full_path)- 1]

"""Function which get all files from server
"""
def GET_ALL():
    GET('index')
    index_file = open("index", 'r')

    for line in index_file:
        FILE = line.strip()
        if (re.search('/', FILE) != None):
            GET("./" + FILE)
        else:
            GET(FILE)


"""Function which get file from server
Args:
    file (string): name of file which will be downloaded from server
"""      
def GET(file):
    
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        tcp_socket.settimeout(50)
        tcp_socket.connect((ip_file_server, port_file_server))   
    except:
        sys.exit("ERR: TCP communication failed")

    request = f"GET {file} FSP/1.0\r\nHostname: {SERVER_NAME}\r\nAgent: {login}\r\n\r\n"

    try:
        tcp_socket.sendall(request.encode())
    except:
        sys.exit("ERR: TCP communication failed")

    count = 0
    while True:
        try:
            if (count == 0):
                try:
                    response = tcp_socket.recv(2048)
                except:
                    sys.exit("No response from server")

                if response == b'':
                    tcp_socket.close()
                    sys.exit("Unexpected response from the server.")
                response = response.split(b"\r\n\r\n", 1)
                if (re.search('Success', response[0].decode("utf-8")) == None):
                    sys.exit(response[1].decode("utf-8"))
                if (response[1] != ''):
                    if (file != '*'):
                        if (re.search('/', file) != None):
                            file = file.split("/")
                            file = (file[len(file) - 1])
                        with open(file, 'wb') as f:
                            f.write(response[1])
                            count += 1
                    else:
                        response = response[1].split(b"\r\n")
                        with open('index', 'wb') as f:
                            for i in range (len(response) - 1):
                                f.write(response[i] + b"\r\n")
                            f.close()

            try:
                response = tcp_socket.recv(2048)
            except:
                sys.exit("No response from server")
            
            if response == b'':
                break
            
            if (count == 1):
                with open(file, 'wb') as f:
                    f.write(response)
            elif (count != 0) and (count > 1):
                if (os.stat(file).st_size != 0):
                    with open(file, 'ab') as f:
                        f.write(response)

            count += 1
        except KeyboardInterrupt: 
            sys.exit()
            
    tcp_socket.close()        


CheckArguments()
login = "xmarko20"

#create UDP socket
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#WHEREIS request to server
MESSAGE = bytes("WHEREIS " + SERVER_NAME, "utf-8")
try:
    udp_socket.sendto(MESSAGE, (format(ipaddress.IPv4Address(IP_ADDRESS)), PORT))
    data, addr = udp_socket.recvfrom(1024) 
except:
    sys.exit("ERR: UDP communication failed")

if data == b'':
    udp_socket.close()
    sys.exit("Unexpected response from the server.")

data = data.decode("utf-8")

if (re.search('ERR', data) != None):
    sys.exit("Server error: " + data)

data = data.split()
data = data[1].split(":")
ip_file_server = data[0]
port_file_server = int(data[1])

if (FILE != '*'):
    GET(FILE)
else:
    GET_ALL()
