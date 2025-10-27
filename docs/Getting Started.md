
# Getting Started

## Option 1

### Server

Download the latest version from [Github Releases](https://github.com/t1b4n3/TibaneC2 )

Run the setup script to setup database and configuration file.
### Client

Download the latest version from [Github Releases](https://github.com/t1b4n3/TibaneC2 )
## Option 2

### Server

I recommend you use a `debain`.

1. Clone the repository

```sh
git clone https://github.com/t1b4n3/TibaneC2 
cd TibaneC2 
```
2.  Run the server installer

```sh
mkdir -p build
sudo ./install-server.sh
```
- This script will install dependencies, setup the database, and add a user.

3.  Verify Installation

```sh
ls ~/.tibane-server-conf.json
ls ./build/tibane-server
```

You see both the server binary and configuration file created.

### Client

1. Install the client 

```sh
sudo ./install-client.sh
```

2. Verify Installation

```sh
ls ./build/tibane-client
```


