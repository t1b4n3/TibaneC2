#!/usr/bin/env bash
set -e

echo "[*] Updating package lists..."
sudo apt update -y

echo "[*] Installing sudo and basic dependencies..."
sudo apt install -y sudo curl wget

echo "[*] Installing required libraries..."
sudo apt install -y \
    libcjson1 \
    libssl3 \
    libmysqlclient21 \
    libcrypt1 \
    libc6 \
    libssl-dev \
    zlib1g-dev \
    zlib1g \
    libcjson-dev \
    libstdc++6 \
    libgcc-s1 \
    build-essential

if apt-cache show libmysqlclient-dev >/dev/null 2>&1; then
    echo "[*] Installing libmysqlclient-dev..."
    sudo apt install -y libmysqlclient-dev
else
    echo "[*] libmysqlclient-dev not found. Installing MariaDB alternatives..."
    sudo apt install -y libmariadb-dev libmariadb-dev-compat
fi

if apt-cache show mysql-server >/dev/null 2>&1; then
    echo "[*] Installing mysql-server..."
    sudo apt install -y mysql-server
else
    echo "[*] mysql-server not found. Installing mariadb-server instead..."
    sudo apt install -y mariadb-server
fi

# Install client package
if apt-cache show mysql-client >/dev/null 2>&1; then
    echo "[*] Installing mysql-client..."
    sudo apt install -y mysql-client
else
    echo "[*] mysql-client not found. Installing mariadb-client-compat instead..."
    sudo apt install -y mariadb-client-compat
fi


if apt-cache show libmysqlclient21 >/dev/null 2>&1; then
    echo "[*] Installing libmysqlclient21 ..."
    sudo apt install -y libmysqlclient21
else
    echo "[*] mysql-client not found. Installing mariadb-client-compat instead..."
    sudo apt install -y libmariadb3
fi

echo "[*] Installing MySQL, Python, and utilities..."
sudo apt install -y \
    python3 \
    apache2-utils \
    jq 

echo "[*] Starting MySQL service..."
# In containers, use this instead of service command
#if [ -d /etc/init.d ]; then
#    /etc/init.d/mysql start
#else
#    # For systemd-less containers
#    mysqld_safe --daemonize
#fi

echo "[*] Waiting for MySQL to start..."
sleep 10  # Give MySQL time to start

echo "[*] Cleaning up..."
sudo apt autoremove -y
sudo apt clean

echo "[*] Done installing libraries and dependencies."

echo
echo "[*] Setting up database..."
read -p "Enter MySQL server (default: localhost): " SERVER
SERVER=${SERVER:-localhost}

read -p "Enter MySQL username (default: root): " DBUSER
DBUSER=${DBUSER:-root}

read -s -p "Enter MySQL password: " DBPASS
echo

read -p "Enter MySQL database to use or create: " DBNAME

# Create the database if it doesn't exist
echo "[*] Ensuring database '$DBNAME' exists..."

# Initialize MySQL if needed and set root password
if [ -z "$DBPASS" ]; then
    # If no password provided, try without password
    mysql -h "$SERVER" -u "$DBUSER" -e "CREATE DATABASE IF NOT EXISTS \`$DBNAME\`;" 2>/dev/null || true
else
    mysql -h "$SERVER" -u "$DBUSER" -p"$DBPASS" -e "CREATE DATABASE IF NOT EXISTS \`$DBNAME\`;" 2>/dev/null || true
fi

# Import schema/data from ./db/setup.sql (if exists)
if [ -f "./db/setup.sql" ]; then
    echo "[*] Importing tables from ./db/setup.sql..."
    
    if [ -z "$DBPASS" ]; then
        mysql -h "$SERVER" -u "$DBUSER" "$DBNAME" < ./db/setup.sql 2>/dev/null || echo "[-] Failed to import schema"
    else
        mysql -h "$SERVER" -u "$DBUSER" -p"$DBPASS" "$DBNAME" < ./db/setup.sql 2>/dev/null || echo "[-] Failed to import schema"
    fi
    echo "[+] Imported ./db/setup.sql successfully."
else
    echo "[-] Warning: ./db/setup.sql not found in current directory, skipping import."
fi

# Escape single quotes for SQL safety
sql_escape() {
    printf "%s" "$1" | sed "s/'/''/g"
}

# Function to add user
AddUsers() {
    local username="$1"
    local password="$2"

    if ! command -v htpasswd >/dev/null 2>&1; then
        echo "[-] Error: apache2-utils not installed."
        return 1
    fi

    ESC_USER="$(sql_escape "$username")"
    ESC_PASS="$(sql_escape "$password")"

    hashed_pw=$(htpasswd -bnBC 12 "" "$ESC_PASS" | tr -d ':\n' | sed 's/^\$2y/\$2b/')

    if [ -z "$DBPASS" ]; then
        mysql -h "$SERVER" -u "$DBUSER" "$DBNAME" -e \
            "INSERT INTO Operators (username, password) VALUES ('$ESC_USER', '$hashed_pw');" 2>/dev/null || echo "[-] Failed to add user"
    else
        mysql -h "$SERVER" -u "$DBUSER" -p"$DBPASS" "$DBNAME" -e \
            "INSERT INTO Operators (username, password) VALUES ('$ESC_USER', '$hashed_pw');" 2>/dev/null || echo "[-] Failed to add user"
    fi
}

echo
read -p "Enter new operator username: " OP_USERNAME
read -s -p "Enter new operator password: " OP_PASSWORD
echo

AddUsers "$OP_USERNAME" "$OP_PASSWORD"

echo "[*] Operator '$OP_USERNAME' added to database '$DBNAME'."

# Build if Makefile exists
if [ -f "./core/Makefile" ]; then
    mkdir -p ./build
    make -C ./core || { echo "[-] Build failed"; exit 1; }
else
    echo "[-] No Makefile found in ./core, skipping build"
fi

# Configuration setup
CONFIG_TEMPLATE="./configuration-templates/server_configuration_template.json"

# Determine the actual user's home
if [ -n "$SUDO_USER" ]; then
    USER_HOME=$(eval echo "~$SUDO_USER")
    TARGET_USER="$SUDO_USER"
else
    USER_HOME="$HOME"
    TARGET_USER=$(whoami)
fi

CONFIG_OUTPUT="$USER_HOME/.tibane-server-conf.json"

echo "[*] Setting up Tibane server configuration..."

if [ -f "$CONFIG_TEMPLATE" ] && command -v jq >/dev/null 2>&1; then
    jq \
      --arg server "$SERVER" \
      --arg user "$DBUSER" \
      --arg pass "$DBPASS" \
      --arg db "$DBNAME" \
      '
      .Database[0].database_server = $server |
      .Database[0].username = $user |
      .Database[0].password = $pass |
      .Database[0].database = $db
      ' "$CONFIG_TEMPLATE" > "$CONFIG_OUTPUT" 2>/dev/null || echo "[-] Failed to create config"

    chmod 600 "$CONFIG_OUTPUT"
    chown $TARGET_USER:$TARGET_USER "$CONFIG_OUTPUT"
    chown $TARGET_USER:$TARGET_USER ./build/tibane-server
    echo "[+] Configuration written to: $CONFIG_OUTPUT"
else
    echo "[-] Config template or jq not available"
fi

echo "[*] Setup complete."