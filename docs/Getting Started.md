
# Getting Started

1. Download the latest release.
2. Setup database `(mysql)` and add at least 1 operator's [`admin`] credentials. 
3. Modify the server configurations in the `config/server_config.json` file according to your needs.
4. Run the server binary `tibane-server` in a Linux host.
5. Run console client `tibane-console` from your preferred platform or use the website.

The following libraries must be installed on the server. 

Linux 
```sh
sudo apt install mingw-x64* \
	libcurl lcjson lcrypto lmysqlclient
```
### setup automatic service

## Compiling from source
