#!/bin/python3
"""
This script emulates fake implants.
Used to send fake traffic to server (now using TCP over SSL/TLS).
"""
import socket
import ssl
import json

HOST = "127.0.0.1"
PORT = 7777

# --- SSL Context Setup ---
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

# If you don’t want cert verification (for testing only):
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

# Create TCP socket and wrap it with SSL
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
agent = context.wrap_socket(sock, server_hostname=HOST)
agent.connect((HOST, PORT))


def register():
    register_msg = """
    {
        "mode": "register",
        "hostname": "nkateko",
        "os": "windows",
        "arch":"x86",
        "mac":"dsfda"
    }
    """
    try:
        data = json.loads(register_msg)
        print("Valid JSON ✅")
    except json.JSONDecodeError as e:
        print("Invalid JSON ❌:", e)

    # Send register
    agent.sendall(register_msg.encode())    
    response = agent.recv(2048)
    print(f"[<] Server responded: {response.decode()}")

    data = json.loads(response)
    print("Type:", data["mode"])
    print("implant_id:", data["implant_id"])


def beacon():
    beacon_msg = """
    {
        "mode":"beacon",
        "implant_id":"f6Cd9nn"  
    }
    """

    try:
        data = json.loads(beacon_msg)
        print("Valid JSON ✅")
    except json.JSONDecodeError as e:
        print("Invalid JSON ❌:", e)

    agent.sendall(beacon_msg.encode())    
    response = agent.recv(4048)
    print(f"[<] Server responded: {response.decode()}")
    data = json.loads(response)

    if data["mode"] == "none":
        print("There are no tasks")
    elif data['mode'] == "task":
        print("Execute Task")
        task_id = data['task_id']
        task = f"""
        {{
            "type":"task",
            "task_id":"{task_id}",
            "implant_id":"f6CIds",
            "response":"nkateko"
        }}
        """
        print("task id: ", task_id)
        print(data.get('command', '[no command]'))

        try:
            data = json.loads(task)
            print("Valid JSON ✅")
        except json.JSONDecodeError as e:
            print("Invalid JSON ❌:", e)

        agent.sendall(task.encode())
    elif data['mode'] == "session":
        session()


def session():
    # rev shell session request
    mode_msg = """
    {
        "mode":"session"
    }
    """
    try:
        data = json.loads(mode_msg)
        print("Valid JSON ✅")
    except json.JSONDecodeError as e:
        print("Invalid JSON ❌:", e)

    agent.sendall(mode_msg.encode())    
    response = agent.recv(4048)
    print(f"[<] Server responded: {response.decode()}")
    data = json.loads(response)    


if __name__ == "__main__":
    #beacon()
    #register()
    beacon()
    agent.close()
