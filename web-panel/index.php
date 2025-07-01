<?php
session_start();

function tasks() {
    // send tasks to core server
}

function agents() {
    // manage agents 
}

// handle operator authentication
function authenticate() {

}

function main() {
    // check if user is logged in first
    if (!isset($_SESSION['login'])) {
        // go to login page
        header("Location: ./login.php");
    } 
}

main();

session_destroy();
?>