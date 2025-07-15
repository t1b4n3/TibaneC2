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
        "mode": "register",
        "agent_id": null,
        "hostname": "nkateko",
        "mac": "xx-xx-yyx-xx",
        "os": "windows",
        "arch":"x86"
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

    print("Type:", data["mode"])
    print("agent_id:", data["agent_id"])

    agent.close()
    

def beacon():
    beacon = """
    {
        "mode":"beacon",
        "agent_id":"dd1048383f5c8b6d02c54d4c77776b198de297ffe98a2aae292ea7d4f9d2147f"   
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

    if data["mode"] == "none":
        print("There are no tasks")
    elif data['mode'] == "task":
        print("Execute Task")
        task_id = data['task_id']
        task = f"""
        {{
            "type":"task",
            "task_id":"{task_id}",
            "agent_id":"a245fd660245555d46a77cb58bf1b373174c63661e42ce196b9cb09a7b425482",
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
    # rev shell
    mode = """
    {
        "mode":"session"
    }
    """

    try:
        data = json.loads(mode)
        print("Valid JSON ✅")
    except json.JSONDecodeError as e:
        print("Invalid JSON ❌:", e)



    #register
    agent.sendall(mode.encode())    
    response = agent.recv(4048)
    print(f"[<] Server responded: {response.decode()}")
    #p = json.dumps(response, indent=4)
    data = json.loads(response)    


if __name__ == "__main__":
    #beacon()
    register()
