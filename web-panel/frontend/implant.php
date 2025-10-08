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

$_SESSION['implant_id'] = $_GET['id'];
$impland_id = $_GET['id'];

if ($_SERVER["REQUEST_METHOD"] == "POST") {
        if (isset($_POST["add_task"]) && isset($_POST["new_task"])) {
                $task = $_POST["new_task"];
                $call_api->add_new_task($impland_id, $task);
        } elseif (isset($_POST['updating_task'])) {
                $task = $_POST["update_task"];
                $task_id = $_POST["task_id"];
                $call_api->update_task($impland_id, $task, $task_id);
        }


}

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
    <a class="navbar-brand" href="./index.php">TibaneC2</a>
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

<?php echo "  ID: $impland_id"; ?>
<br>

<hr>
<form method='post'>
        <label> New Task : </label> <input name='new_task' type='text'>
        <button type='submit' name='add_task'>Add Task</button>
</form>
<hr>
<form method='post'>
        <h3>Update Task </h3>
        <label> Task </label> <input name='update_task' type='text'> <br>
        <label> Task ID </label> <input name='task_id' type='number'> 
        <buttom type='submit' name='updating_task'> Update Task</button>
</form>



</body>
<html>