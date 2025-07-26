

```sh
sudo apt install libcjson-dev libreadline-dev
sudo apt install libreadline-dev:amd64 libcjson-dev:amd64

```


### 1 Configure
- Run [database setup script](./db/setup.sql) in mysql to setup database and add at least 1 operator credentials manaully.
- Modify [server](./config/server_conf.json) and [console](./config/console_conf.json) configuration files as needed.

### 2. Build the Core Server
```bash
cd core
make
./tibane-server
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
./tibane-console
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

