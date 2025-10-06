<?php 
session_start();

require_once "api.php";

// is user logged in
if (empty($_SESSION['user'])) {
        header("Location: ./login.php");
        exit();
}

$url = "http://localhost:8000";
$call_api = new CallApi($url);

$impland_id = $_SESSION['implant_id'];

?>


<!DOCTYPE html>
<html>
    <head>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  
    </head>
    <body>

	<!-- Navbar -->
<nav class="navbar navbar-expand-lg bg-body-tertiary">
  <div class="container-fluid">
    <a class="navbar-brand" href="./index.php">TibaneC2 Web Client</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
      <ul class="navbar-nav">
        <li class="nav-item">
          <a class="nav-link active" aria-current="page" href="././index.php">Home</a>
        </li>
        <li class="nav-item">
          <a class="nav-link" href="./tasks.php">Tasks</a>
        </li>
	<li class="nav-item">
        	<a class="nav-link" href="./logout.php">Logout</a>
        </li>
      </ul>
    </div>
  </div>
</nav>

<br>


<form method='post'>
        <label>

</form>




</body>
<html>