
# Getting Started

## Option 1

1. Clone the repository

```sh
git clone https://github.com/tibane0TibaneC2 
cd TibaneC2
```
2.  Run the server installer

```sh
sudo ./install-server.sh
```
- This script will install dependencies, setup the database, and add a user.

3.  Verify Installation

```sh
ls ~/.tibane-server-conf.json
ls ./build/tibane-server
```

You see both the server binary and configuration file created.

4. Install the client installer

```sh
sudo ./install-client.sh
```

5. Run both the server and client in different terminals

```sh
./build/tibane-server
./build/tibane-client

```


