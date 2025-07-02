<?php 

require_once "c2.php";

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
        <label for="username" class="form-label">Username</label>
        <input type="text" class="form-control" id="username" name="username" required>
      </div>

      <div class="mb-3">
        <label for="password" class="form-label">Password</label>
        <input type="password" class="form-control" id="password" name="password" required>
      </div>

      <button type="submit" class="btn btn-primary w-100">Login</button>
    </form>
  </div>

</body>
</html>

<?php


function main() {
  if (isset($_POST['username']) && isset($_POST['password'])) {
    if (authenticate($_POST['username'], $_POST_['password']) == 0) {
        $_SESSION['login'] = $_POST['username'];
        header("Location: ./index.php");
        exit();
    }  else {
        echo "Invalid Credentials";      
    }
  }
}


if (isset($_POST['log-in'])) {
    main();
}
?>