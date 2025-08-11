
# Getting Started

1. Download the latest release.
2. Setup database `(mysql)` and add at least 1 operator's  credentials using this script [Add_Users.py](../scripts/add_user.py). 
3. Modify the server configurations in the `tibane_server_conf.json` file that is in the same directory as the `tibane_serveraccording to your needs.
4. Run the server binary `tibane_server` in a Linux host.
5. Run console client `tibane-console` from your preferred platform or use the website.

The following libraries must be installed on the server. 

Linux 
```sh
sudo apt install mingw-x64* \
	libcurl lcjson lcrypto lmysqlclient \
	libcjson-dev libreadline-dev \ 
	gcc gcc-multilib g++ g++-multilib
```
### setup automatic service


[Compile From Source](./compiling_from_source.md)
