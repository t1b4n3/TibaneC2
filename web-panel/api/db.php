<?php
#$host = 'localhost';
$host = '127.0.0.1';
$dbname = 'c2_database';
$username = 'core';
$password = 'core';
try {
$pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
die("Database connection failed: " . $e->getMessage());
}
?>