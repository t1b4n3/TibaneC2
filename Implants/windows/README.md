# Implant
The implant is a native Windows application that:
- Connects to the server over TLS using Schannel
- Executes commands received from the server
- Returns the output via the secure channel

### Features
- Uses Schannel for TLS (no OpenSSL dependency)
- Lightweight and written in pure C
- Executes commands using _popen