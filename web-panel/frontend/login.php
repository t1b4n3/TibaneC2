<?php 
session_start();

require_once "api.php";

function main() {
  $api = new CallApi("http://localhost:8000");
  if (isset($_POST['Username']) && isset($_POST['Password'])) {
        $authenticate = $api->auth($_POST['Username'], $_POST['Password']);
        if ($authenticate['Authenticate'] == true) {
                $_SESSION['user'] = $_POST['Username'];
                $_SESSION['logged_in_at'] = time();
                header("Location: ./index.php");
                exit();
        }  else {
            //echo "\n\n\n Invalid Credentials";      
        }
  }
}


if ($_SERVER["REQUEST_METHOD"] == "POST") {
    main();
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Login</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    html, body {
      height: 100%;
      margin: 0;
    }
  </style>
</head>
<body class="d-flex justify-content-center align-items-center bg-light" style="height: 100vh;">

  <div class="p-4 shadow rounded bg-white" style="width: 100%; max-width: 400px;">
    <form method="POST">
      <div class="mb-3">
        <label for="Username" class="form-label">Username</label>
        <input type="text" class="form-control" id="username" name="Username" required>
      </div>

      <div class="mb-3">
        <label for="Password" class="form-label">Password</label>
        <input type="password" class="form-control" id="password" name="Password" required>
      </div>

      <button type="submit" name='log-in' class="btn btn-primary w-100">Login</button>
    </form>
  </div>

</body>
</html>
