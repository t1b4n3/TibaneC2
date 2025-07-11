#!/bin/python3
from socket import *
import json

HOST = "127.0.0.1"
PORT = 8888

operator = socket(AF_INET, SOCK_STREAM)
operator.connect((HOST, PORT))

def login():
    credentials = """
    {
        "username":"user",
        "password":"pass"
    }
    """

    try:
        data = json.loads(credentials)
    except json.JSONDecodeError as e:
        print("Invalid json :", e)

    operator.sendall(credentials.encode())

    response = operator.recv(2048)
    print(f"[<] Server responded: {response.decode()}")

    #p = json.dumps(response, indent=4)
    data = json.loads(response)

    if data['operator'] == "true":
        print("Authenticated")
    elif data['operator'] == "false":
        print("NOT Valid Creds")
        exit()


def get_info(about):
    a = f"""
    {{
        "Info":"{about}"
    }}
    """
    try:
        data = json.loads(a)
    except json.JSONDecodeError as e:
        print("Invalid json :", e)
        exit()
    operator.sendall(a.encode())

    # recv data
    response = operator.recv(2048)
    print(f"[<] Server responded: {response.decode()}")

    data = json.loads(response)
    count = len(data)

    #print(data)


def tasks_per_agent():
    a = """
    {
        "Info":"agent_id",
        "agent_id":"a245fd660245555d46a77cb58bf1b373174c63661e42ce196b9cb09a7b425482"
    }
    """
    try:
        data = json.loads(a)
    except json.JSONDecodeError as e:
        print("Invalid json :", e)

    operator.sendall(a.encode())
    response = operator.recv(2048)
    print(f"[<] Server responded: {response.decode()}")


def add_new_task():
    a = """
    {
        "Info":"new_task",
        "agent_id":"a47505de64adaefc253cd1c27751da77587710e876aac229bc8032edbc8d775b",
        "command":"ls -lha"
    }   
    """
    try:
        data = json.loads(a)
    except json.JSONDecodeError as e:
        print("Invalid json :", e)

    operator.sendall(a.encode())
    response = operator.recv(2048)
    print(f"[<] Server responded: {response.decode()}")


if __name__ == "__main__":
    login()
    #get_agent_info()
    #add_new_task()
    tasks_per_agent()

    #about = ["Agents", "Tasks"]
    #for x in about:
    #    get_info(x);


