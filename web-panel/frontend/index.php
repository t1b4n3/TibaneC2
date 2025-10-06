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

$implant_data = json_decode($call_api->get_all_implants(), true);

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
          <a class="nav-link active" aria-current="page" href="./index.php">Home</a>
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
<h2>HELLO <?php echo htmlspecialchars($_SESSION['user']); ?></h2>


    <h3>Implant Information</h3>
    <?php if (!empty($implant_data)): ?>
    <table class="table">
        <thead lass="thead-dark">
            <tr>
                <th scope='col'>#</th>
                <th scope="col">Implant ID</th>
                <th scope="col">Operating System</th>
                <th scope="col">IP address</th>
		<th scope="col">Architecture</th>
                <th scope="col">Hostname</th>
                <th scope="col">Last Seen</th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($implant_data as $i => $data): ?>
            <tr>
                <th scope="row"><?php echo $i + 1; ?></th>
                <td><?php echo htmlspecialchars($data['implant_id']); ?></td> 
                <td><?php echo htmlspecialchars($data['os']); ?></td>
                <td><?php echo htmlspecialchars($data['ip']); ?></td>
                <td><?php echo htmlspecialchars($data['arch']); ?></td>
                <td><?php echo htmlspecialchars($data['hostname']); ?></td>
                <td><?php echo htmlspecialchars($data['last_seen']); ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php else: ?>
        <h3>No Implant data available.</h3>
    <?php endif; ?>

    </body>
</html>
