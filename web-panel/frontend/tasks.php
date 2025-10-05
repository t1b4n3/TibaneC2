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

$tasks_data = json_decode($call_api->get_all_tasks(), true);

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


    <h3>Tasks Information</h3>
    <?php if (!empty($tasks_data)): ?>
    <table class="table">
        <thead lass="thead-dark">
            <tr>
                <th scope='col'>Task ID</th>
                <th scope="col">Implant ID</th>
                <th scope="col">Command</th>
                <th scope="col">Response</th>
		<th scope="col">Status</th>

            </tr>
        </thead>
        <tbody>
        <?php foreach ($tasks_data as $i => $data): ?>
            <tr>
               <td><?php echo htmlspecialchars($data['task_id']); ?></td>
                <td><?php echo htmlspecialchars($data['implant_id']); ?></td>
                <td><?php echo htmlspecialchars($data['command']); ?></td>
                <td><?php echo htmlspecialchars((string)$data['response']); ?></td>
                <td><?php echo ($data['status'] == 0) ? "Pending" : "Completed"; ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php else: ?>
        <h5>No task data available.</h5>
    <?php endif; ?>



    </body>
</html>
