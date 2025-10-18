#!/usr/bin/env bash
set -e

# ================================
# Docker-friendly non-interactive installer
# ================================

# Defaults via environment variables
SERVER="${SERVER:-localhost}"
DBUSER="${DBUSER:-tibaneuser}"
DBPASS="${DBPASS:-tibanepass}"
OP_USERNAME="${OP_USERNAME:-admin}"
OP_PASSWORD="${OP_PASSWORD:-admin123}"

DBNAM="tibaneC2-server"

echo "[*] Updating package lists..."
apt update -y

echo "[*] Installing required packages..."
apt install -y \
    build-essential \
    curl wget git \
    mariadb-server mariadb-client \
    libmariadb-dev libmariadb-dev-compat \
    libssl-dev zlib1g-dev libcjson-dev \
    python3 apache2-utils jq \
    && apt clean

# Start MariaDB in the background
echo "[*] Starting MariaDB..."
mysqld_safe --datadir=/var/lib/mysql --skip-networking=0 &
sleep 10  # wait for DB to be ready

# ================================
# SQL escape function
# ================================
sql_escape() {
    printf "%s" "$1" | sed "s/'/''/g"
}

ESC_USER="$(sql_escape "$DBUSER")"
ESC_PASS="$(sql_escape "$DBPASS")"
ESC_DB="$(sql_escape "$DBNAME")"

# ================================
# Create database and user
# ================================
echo "[*] Setting up database and user..."
mysql -u root -e "CREATE DATABASE IF NOT EXISTS \`$ESC_DB\`;"
mysql -u root -e "CREATE USER IF NOT EXISTS '$ESC_USER'@'%' IDENTIFIED BY '$ESC_PASS';"
mysql -u root -e "GRANT ALL PRIVILEGES ON \`$ESC_DB\`.* TO '$ESC_USER'@'%';"
mysql -u root -e "FLUSH PRIVILEGES;"

# ================================
# Import schema
# ================================
if [ -f ./db/setup.sql ]; then
    echo "[*] Importing tables from ./db/setup.sql..."
    mysql -u "$DBUSER" -p"$DBPASS" "$DBNAME" < ./db/setup.sql
    echo "[+] Imported ./db/setup.sql successfully."
else
    echo "[-] ./db/setup.sql not found, skipping import."
fi

# ================================
# Add operator
# ================================
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

    mysql -u "$DBUSER" -p"$DBPASS" "$DBNAME" -e \
        "INSERT INTO Operators (username, password) VALUES ('$ESC_USER', '$hashed_pw');" \
        2>/dev/null || echo "[-] Failed to add operator"
}

echo "[*] Adding operator '$OP_USERNAME'..."
AddUsers "$OP_USERNAME" "$OP_PASSWORD"
echo "[+] Operator '$OP_USERNAME' added to database '$DBNAME'."

# ================================
# Build Tibane server if Makefile exists
# ================================
if [ -f ./core/Makefile ]; then
    mkdir -p ./build
    echo "[*] Building Tibane server..."
    make -C ./core || { echo "[-] Build failed"; exit 1; }
else
    echo "[-] No Makefile found in ./core, skipping build."
fi

# ================================
# Setup configuration
# ================================
CONFIG_TEMPLATE="./configuration-templates/server_configuration_template.json"
USER_HOME="/root"
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
    chown root:root "$CONFIG_OUTPUT"
    chown root:root ./build/tibane-server
    echo "[+] Configuration written to: $CONFIG_OUTPUT"
else
    echo "[-] Config template or jq not available, skipping configuration."
fi

echo "[*] Installation complete."
