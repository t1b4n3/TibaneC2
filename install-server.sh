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
    libcrypt1 \
    libc6 \
    libssl-dev \
    zlib1g-dev \
    zlib1g \
    libcjson-dev \
    libstdc++6 \
    libgcc-s1 \
    build-essential


sudo apt install -y \
    libmysqlclient-dev \
    mysql-server mysql-client \
    libmysqlclient21


echo "[*] Installing MySQL, Python, and utilities..."
sudo apt install -y \
    python3 \
    apache2-utils \
    jq 

echo "[*] Starting MySQL service..."
# In containers, use this instead of service command
# For systemd-less containers
if ! pgrep -x "mysqld" > /dev/null; then
    echo "[*] Starting MySQL service..."
    sudo mysqld_safe  
else
    echo "[*] MySQL is already running."
fi

echo "[*] Waiting for MySQL to start..."
sleep 10  # Give MySQL time to start

echo "[*] Cleaning up..."
sudo apt autoremove -y
sudo apt clean

echo "[*] Done installing libraries and dependencies."

echo
echo "[*] Setting up database..."

sql_escape() {
    echo "$1" | sed "s/'/\\\\'/g; s/\"/\\\\\"/g; s/\\/\\\\//g"
}

read -p "Enter MySQL server (default: localhost): " SERVER
SERVER=${SERVER:-localhost}

read -p "Enter MySQL username (default: root): " DBUSER
DBUSER=${DBUSER:-root}

read -s -p "Enter MySQL password: " DBPASS
echo

DBNAME="tibane_server"

ESC_USER="$(sql_escape "$DBUSER")"
ESC_PASS="$(sql_escape "$DBPASS")"
ESC_DB="$(sql_escape "$DBNAME")"

SQL=$(cat <<EOF
CREATE USER IF NOT EXISTS '${ESC_USER}'@'localhost' IDENTIFIED BY '${ESC_PASS}';
GRANT ALL PRIVILEGES ON \`${ESC_DB}\`.* TO '${ESC_USER}'@'localhost';
FLUSH PRIVILEGES;
EOF
)

# Try to run via sudo mysql (no password) — best on many Linux distros.
if sudo mysql -e "SELECT 1;" >/dev/null 2>&1; then
  echo "[*] Using sudo mysql (socket/auth) to run SQL..."
  echo "$SQL" | sudo mysql || { echo "[-] Failed to execute SQL via sudo mysql"; exit 1; }
  echo "[+] User '$DBUSER' created / granted on '$DBNAME' (via sudo)."
fi

# If sudo mysql didn't work, prompt for MySQL root password and use a secure defaults file.
read -s -p "Enter MySQL root password: " ROOT_MYSQL_PASS
echo

# Create temporary defaults file to avoid exposing the password on command line
TMP_CNF="$(mktemp)"
chmod 600 "$TMP_CNF"
cat >"$TMP_CNF" <<EOF
[client]
user=root
password=${ROOT_MYSQL_PASS}
host=localhost
EOF

# Execute SQL using the temporary config
if mysql --defaults-extra-file="$TMP_CNF" -e "$SQL"; then
  echo "[+] User '$DBUSER' created / granted on '$DBNAME' (via provided root password)."
  # destroy temp file securely
  shred -u "$TMP_CNF" 2>/dev/null || rm -f "$TMP_CNF"
else
  echo "[-] Failed to execute SQL using provided root password."
  shred -u "$TMP_CNF" 2>/dev/null || rm -f "$TMP_CNF"
fi



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

    # Check if the file is readable
    if [ ! -r "./db/setup.sql" ]; then
        echo "[-] Error: ./db/setup.sql is not readable. Check file permissions."
        exit 1
    fi
    
    # MySQL import command
    if [ -z "$DBPASS" ]; then
        # If DBPASS is not provided, use the default user passwordless connection
        echo "[*] Importing schema without password..."
        mysql -h "$SERVER" -u "$DBUSER" "$DBNAME" < ./db/setup.sql
        if [ $? -ne 0 ]; then
            echo "[-] Failed to import schema. Check MySQL server, user permissions, and the setup.sql file."
            exit 1
        fi
    else
        # If DBPASS is provided, use it for the MySQL connection
        echo "[*] Importing schema with password..."
        mysql -h "$SERVER" -u "$DBUSER" -p"$DBPASS" "$DBNAME" < ./db/setup.sql
        if [ $? -ne 0 ]; then
            echo "[-] Failed to import schema. Check MySQL server, user permissions, and the setup.sql file."
            exit 1
        fi
    fi

    echo "[*] Schema imported successfully."

else
    echo "[-] Warning: ./db/setup.sql not found in current directory, skipping import."
fi
# Escape single quotes for SQL safety

# Function to add user
AddUsers() {
    local username="$1"
    local password="$2"

    # Check if htpasswd is installed
    if ! command -v htpasswd >/dev/null 2>&1; then
        echo "[-] Error: apache2-utils not installed."
        return 1
    fi

    # Escape user input to prevent SQL injection
    ESC_USER="$(sql_escape "$username")"
    ESC_PASS="$(sql_escape "$password")"

    # Hash the password using htpasswd
    hashed_pw=$(htpasswd -bnBC 12 "" "$ESC_PASS" | tr -d ':\n' | sed 's/^\$2y/\$2b/')

    # Check if DBPASS is provided for MySQL login
    if [ -z "$DBPASS" ]; then
        # Using default MySQL credentials (no password)
        mysql -h "$SERVER" -u "$DBUSER" "$DBNAME" -e \
            "INSERT INTO Operators (username, password) VALUES ('$ESC_USER', '$hashed_pw');"
        if [ $? -ne 0 ]; then
            echo "[-] Failed to add user (no DBPASS provided)."
        fi
    else
        # Using provided MySQL password
        mysql -h "$SERVER" -u "$DBUSER" -p"$DBPASS" "$DBNAME" -e \
            "INSERT INTO Operators (username, password) VALUES ('$ESC_USER', '$hashed_pw');"
        if [ $? -ne 0 ]; then
            echo "[-] Failed to add user (with DBPASS provided)."
        fi
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