# Basic C2

Basic-C2 is a minimalist Command and Control (C2) framework built from scratch in C. It was developed purely for educational purposes to better understand how C2 infrastructure operates at a low level — especially regarding encrypted communication, socket programming, and remote execution.

[Blog Post](https://nkatekotibane.github.io/posts/basic-c2/)

#### Goal
- Build a working implant in C that:
- Connects to a Linux-based C2 server using TLS
- Receives and executes remote commands securely
- Returns command output back to the server


### Project Structure
- Server/ linux-based C2 server using OpenSSl
- Implant/ Windows-based implant

## USAGE

All the code is compiled in linux

### C2 server

```sh
make
```


### Windows

```sh
make
```


## FEATURES/FUNCTIONALITY TO ADD IN THE C2 INFRASTRUCTURE
- logging via database
- staging server
- communication channels (http/dns/tcp)
- redirector
- copy files/scripts to target
- exfilitrate files
- web panel (GUI)


