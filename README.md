# TibaneC2 - Command & Control Framework

**TibaneC2** is a fully custom-built Command & Control (C2) framework designed for offensive security research, red teaming, and adversary simulation. It includes a native C/C++ core server, a PHP-based web panel, a CLI console, cross-platform implants, multi-language stagers, and scripting tools for automation and emulation.

> ⚠️ For educational and authorized testing purposes only.

[Already have basic C2 implementation](./BasicC2/README.md) 

The goal is to keep the C2 framework modular by splitting it into clear components, where each component will follow a defined interface so I can swap or add features easily, That way i can extend it without touching the core logic.

---

## Project Components

| Component      | Language(s)                     | Description |
|----------------|----------------------------------|-------------|
| **Core Server** | C                           | Central server that communicates with implants and operator interfaces |
| **Web Panel**   | PHP                              | Web-based control interface for managing agents and sending tasks |
| **CLI Console** | C++                               | Terminal-based operator tool for environments without a GUI |
| **Implants**    | C, C++ ,Python, Powershell, Bash                            | Persistent agents that execute commands and exfiltrate data |
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
├── core/ # C Core server logic
├── web-panel/ # Web panel (PHP)
├── cli-console/ # CLI interface (C++)
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


## Communication Methods

- **Custom TCP communication:** Communicates via custom tcp and sends data via json
### Planned
- **Encrypted TCP Communication:** Encrypt communications (ssl/tls)
- **HTTP/HTTPS:** Web traffic to blend in with normal traffic


## Getting Started
### 1 Configure
- Run [database setup script](./db/setup.sql) in mysql to setup database and add at least 1 operator manully.
- Modify [server](./config/server_conf.json) and [console](./config/console_conf.json) configuration files as needed.
### 2. Build the Core Server
```bash
cd core
make
./c2_server
```

### 3. Run the Web Panel
**NOT YET BUILD**  
Host PHP files via Apache/Nginx or PHP’s built-in server:
On the same machine as the core server

```bash
php -S localhost:8080 -t web-panel/
```
> #### OR

### 3. Run the CLI Console

```bash
cd cli-console
make
./cli_console
```

### 4. Deploy an Implant
Compile or obfuscate from implants/

Use stagers/ to deliver the payload

## Tooling & Automation
|Script |Description |
|:---|---:|
|payload_generator.py | Generate obfuscated payloads |
|health_check.sh | Check server and DB health|
|emulator.py |Simulate agent traffic |

-- 
## TODO
### Core server
- Implement Logging
- Session mode
- HTTP/HTTPS Communication methods
- Encrypted Communication 

### Implants
- keylogger
- screenshot capture
- file upload/download
- sandbox and vm detection checks
- kill switch for self-removal
- persistence mechanisms

### Web-panel 
- Authentication 

--  

> Legal Notice
> This project is for educational and authorized testing purposes only. Unauthorized use of this tool may violate local, state, or international laws. You are responsible for using this project ethically and legally.


## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
