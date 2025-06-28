# TibaneC2 - Command & Control Framework

**TibaneC2** is a fully custom-built Command & Control (C2) framework designed for offensive security research, red teaming, and adversary simulation. It includes a native C/C++ core server, a PHP-based web panel, a CLI console, cross-platform implants, multi-language stagers, and scripting tools for automation and emulation.

> ⚠️ For educational and authorized testing purposes only.


[Already have basic C2 implementation](./BasicC2/README.md) 

---

## Project Components

| Component      | Language(s)                     | Description |
|----------------|----------------------------------|-------------|
| **Core Server** | C/C++                           | Central server that communicates with implants and operator interfaces |
| **Web Panel**   | PHP                              | Web-based control interface for managing agents and sending tasks |
| **CLI Console** | C                                | Terminal-based operator tool for environments without a GUI |
| **Implants**    | C/C++                            | Persistent agents that execute commands and exfiltrate data |
| **Stagers**     | Assembly, C, Python, Bash, PowerShell | Lightweight loaders to deploy implants |
| **Database**    | MySQL              | Tracks agents, tasks, results, logs |
| **Automation**  | Python / Bash                    | Tools for payload generation, system health checks, and threat simulation |

---

## Architecture Overview

```yaml
[ Web Panel (PHP) ] ┐
                     ├──> [ Core Server (C++) ] <──> [ Implant (C++) ]
[ CLI Console (C) ] ┘                           ▲
                                                │
                                                [ Stagers (ASM/C/PS/Py/Bash) ]
```

## Directory Structure
 ```yaml

TibaneC2/
├── core/ # C/C++ Core server logic
├── panel/ # Web panel (PHP)
├── cli/ # CLI interface (C)
├── implants/ # Cross-platform agents
├── stagers/ # Initial access payloads
├── db/ # Database setup/scripts
├── scripts/ # Automation tools
├── docs/ # Diagrams and documentation
└── README.md # Project descriptiion
 ```

## Features

- Multi-agent support with task queueing
- CLI and Web-based control interfaces
- Encrypted C2 communication (planned: AES/TLS)
- File upload/download and command execution
- Stagers for rapid deployment
- Persistent implant options (Windows & Linux)
- Central logging, audit trail, and command results
- Payload obfuscation and delivery automation


## Getting Started

### 1. Build the Core Server
```bash
cd core
make
./c2_server
```

### 2. Run the Web Panel
Host PHP files via Apache/Nginx or PHP’s built-in server:

```bash
php -S localhost:8080 -t panel/
```

## OR

### 2. Run the CLI Console

```bash
cd cli
make
./console
```

### 3. Deploy an Implant
Compile or obfuscate from implants/

Use stagers/ to deliver the payload



## Database Schema (example)
agents (id, hostname, os, last_seen, ip)

tasks (id, agent_id, command, status, result)

logs (timestamp, type, message)

## Tooling & Automation
Script	Description
payload_generator.py	Generate obfuscated payloads
health_check.sh	Check server and DB health
emulator.py	Simulate agent traffic

🧪 Development Roadmap
 Core TCP server

 Web interface integration

 CLI console tool

 Implant command execution

 File transfer

 Encrypted comms (AES/TLS)

 HTTP/S-based fallback C2

 Anti-analysis and OPSEC evasion

 SOCKS proxy tunneling

 Plugin-based extension system

⚠️ Legal Notice
This project is for educational and authorized testing purposes only. Unauthorized use of this tool may violate local, state, or international laws. You are responsible for using this project ethically and legally.

👨‍💻 Author
Developed by Laporte
For research, learning, and C2 framework development practice.

