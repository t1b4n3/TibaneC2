from socket import *
import json

HOST = "127.0.0.1"
PORT = 9999

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


agent = socket(AF_INET, SOCK_STREAM)
agent.connect((HOST, PORT))
#register
agent.sendall(beacon.encode())    
response = agent.recv(2048)
print(f"[<] Server responded: {response.decode()}")
#p = json.dumps(response, indent=4)
data = json.loads(response)

if data["type"] == "nope":
    print("There are no tasks")
elif data['type'] == "task":
    print("Execute Task")

    task = """
    {
        "type":"result",
        "task_id":"123",
        "agent_id":"xxx",
        "output":"nkateko"
    }
    """

    try:
        data = json.loads(task)
        print("Valid JSON ✅")
    except json.JSONDecodeError as e:
        print("Invalid JSON ❌:", e)

    agent.sendall(task.encode())