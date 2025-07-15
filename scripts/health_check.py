'''
build a port scanner which scans and checks if server is still on (both ports) and db is still working
'''

def server(ip, agentPort, operatorPort, dbPort):
    """
    check if server is live and if c2 software is running (for both ports)
    
    1. send ICMP Echo request to server to check if running (10 packets)
    2. port scan for all database, agent and operator ports
    """
    pass

if __name__ == "__main__":
    agentPort = 9999
    operatorPort = 8888
    dbPort = 333
    ip = "127.0.0.1"

    server(ip, agentPort, operatorPort, dbPort)    


