#!/bin/python3
"""
This script is used to emulate fake implants.
Used to send fake traffic to server to make sure it works as intended
"""
from socket import *
import json

HOST = "127.0.0.1"
PORT = 9999

agent = socket(AF_INET, SOCK_STREAM)
agent.connect((HOST, PORT))
# tcp traffic w/o ssl/tls
def register():
    register = """
    {
        "type": "register",
        "agent_id": null,
        "hostname": "kali",
        "mac": "xx-xx-yy-xx",
        "os": "windows"
    }
    """
    try:
        data = json.loads(register)
        print("Valid JSON ✅")
    except json.JSONDecodeError as e:
        print("Invalid JSON ❌:", e)

    #register
    agent.sendall(register.encode())    
    response = agent.recv(2048)
    print(f"[<] Server responded: {response.decode()}")

    #p = json.dumps(response, indent=4)
    data = json.loads(response)

    print("Type:", data["type"])
    print("agent_id:", data["agent_id"])

    agent.close()
    

def beacon():
    beacon = """
    {
        "type":"beacon",
        "agent_id":"a245fd660245555d46a77cb58bf1b373174c63661e42ce196b9cb09a7b425482"   
    }
    """

    try:
        data = json.loads(beacon)
        print("Valid JSON ✅")
    except json.JSONDecodeError as e:
        print("Invalid JSON ❌:", e)



    #register
    agent.sendall(beacon.encode())    
    response = agent.recv(4048)
    print(f"[<] Server responded: {response.decode()}")
    #p = json.dumps(response, indent=4)
    data = json.loads(response)

    if data["type"] == "nope":
        print("There are no tasks")
    elif data['type'] == "task":
        print("Execute Task")
        task_id = data['task_id']
        task = f"""
        {{
            "type":"{task_id}",
            "task_id":"1",
            "agent_id":"a245fd660245555d46a77cb58bf1b373174c63661e42ce196b9cb09a7b425482",
            "output":"nkateko"
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


if __name__ == "__main__":
    beacon()