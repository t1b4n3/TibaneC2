# Use Ubuntu 22.04 base
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV DBUSER=tibaneuser
ENV DBPASS=tibanepass
ENV MYSQL_ROOT_PASSWORD=rootpass
ENV SERVER=localhost

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl wget build-essential git \
    mariadb-server mariadb-client \
    libmariadb-dev libmariadb-dev-compat \
    libssl-dev zlib1g-dev libcjson-dev python3 apache2-utils jq \
    && rm -rf /var/lib/apt/lists/*

# Copy TibaneC2 source
COPY . /tibaneC2
WORKDIR /tibaneC2

# Make install script executable
RUN chmod +x install-server.sh

# Start the script automatically
CMD ["bash", "/tibaneC2/install.sh"]
