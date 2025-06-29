#!/bin/python3
"""
This script is used to emulate fake implants.
Used to send fake traffic to server to make sure it works as intended
"""
from socket import *
import json

HOST = "127.0.0.1"
PORT = 9999

register = """
{
    "type": "register",
    "agent_id": null,
    "hostname": "laporte",
    "mac": "xx-xx-xx",
    "os": "linux"
}
"""
# tcp traffic w/o ssl/tls
def tcp():
    try:
        data = json.loads(register)
        print("Valid JSON ✅")
    except json.JSONDecodeError as e:
        print("Invalid JSON ❌:", e)


    agent = socket(AF_INET, SOCK_STREAM)
    agent.connect((HOST, PORT))
    #register
    agent.sendall(register.encode())    
    response = agent.recv(2048)
    print(f"[<] Server responded: {response.decode()}")

    #p = json.dumps(response, indent=4)
    data = json.loads(response)

    print("Type:", data["type"])
    print("agent_id:", data["agent_id"])

    agent.close()
    pass


if __name__ == "__main__":
    tcp()