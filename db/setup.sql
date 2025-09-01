CREATE DATABASE IF NOT EXISTS Command_and_Control

USE Command_and_Control

CREATE TABLE IF NOT EXISTS Implants (
    implant_id VARCHAR(8) PRIMARY KEY,
    os VARCHAR(50),
    ip VARCHAR(50),
    arch VARCHAR(50),
    hostname VARCHAR(255),
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS logs (
    implant_id VARCHAR(66) PRIMARY KEY,
    log_type ENUM('INFO', 'ERROR', 'COMMAND'),
    message TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS Tasks (
    task_id int AUTO_INCREMENT PRIMARY KEY,
    implant_id VARCHAR(8),
    command TEXT,
    response LONGBLOB DEFAULT NULL,
    status BOOLEAN DEFAULT FALSE,    
    FOREIGN KEY (implant_id) REFERENCES Implants(implant_id)
);

CREATE TABLE IF NOT EXISTS Operators (
    operator_id int AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(250) NOT NULL
);
