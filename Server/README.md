# Command and Control Server
The server is lightweight and runs on Linux. It sets up a secure TLS listener using OpenSSL, accepts multiple incoming client connections, and uses pthreads to handle each client concurrently.

Features
TLS-based encrypted communication using OpenSSL

Multi-threaded support for concurrent implants

Command forwarding and output logging