#!/bin/python3
"""
This script is used to emulate fake implants.
Used to send fake traffic to server to make sure it works as intended
"""
from socket import *

HOST = "127.0.0.1"
PORT = 9999

register = """
{
	"type":"register",
	"hostname":"python-em",
	"os":"linux",
	"arch":"x64",
	"ip":"12"
}
"""


# tcp traffic w/o ssl/tls
def tcp():
    agent = socket(AF_INET, SOCK_STREAM)
    agent.connect((HOST, PORT))
    #register
    agent.sendall(register.encode())    
    response = agent.recv(2048)
    print(f"[<] Server responded: {response.decode()}")

    agent.close()
    pass

#tcp traffic w/ ssl/tls
def tcp_ssl():
    pass

# http traffic 
def http():
    pass

# https traffic
def https():
    pass

def main():
    pass

if __name__ == "__main__":
    main()