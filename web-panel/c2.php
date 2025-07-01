<?php 
$c2 = "127.0.0.1";
$port = 9999;

function onSocketFailure(string $message, $socket = null) {
    if(is_resource($socket)) {
    $message .= ": " . socket_strerror(socket_last_error($socket));
    }
    die($message);
   }


$socket = socket_create(AF_INET, SOCK_SREAM, SOL_TCP);
if(!is_resource($socket)) onSocketFailure("Failed to create socket");
$socket_connect($socket, $c2, $port) or onSocketFailure("Failed to connect to c2 server", $socket);

function authenticate($username, $password) {
    $creds = [
        'username' => $username,
        'password' => $password
    ];

    $credentials = json_encode($creds);
    #$sock = $_SESSION['sock'];


    // send over socket to core server
    socket_write($socket, $credentials);

    // wait to recieve if authenticated
    $response = socket_read(socket, 1024);
    $auth = json_decode($response);
    if ($auth->operator == "true") {
        return 0;
    } else {
        return -1; 
    }
}


function AgentInfo() {
    
}






?>