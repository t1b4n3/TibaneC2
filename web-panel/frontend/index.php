<?php 
session_start();

require_once "api.php";


function main() {
    // is user logged in?
    $url = "http://localhost:8000";
    $call_api = new CallApi($url);
    //if (empty($_SESSION['login'])) {
    //    if (!isset($_SESSION['login'])) {
    //        // go to login page
    //        header("Location: ./login.php");
    //        exit();
    //    }   
    //}
    $implant_data = $call_api->get_all_implants();
}

main();

?>

<!DOCTYPE html>
<html>
    <head>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  
    </head>
    <body>
    <h3>Agent Information</h3>
    <?php if (!empty($implant_data['implant_id'])): ?>
    <table class="table">
        <thead lass="thead-dark">
            <tr>
                <th scope='col'>#</th>
                <th scope="col">Agent ID</th>
                <th scope="col">Operating System</th>
                <th scope="col">IP address</th>
                <th scope="col">Hostname</th>
                <th scope="col">Last Seen</th>
            </tr>
        </thead>
        <tbody>
            <?php for ($i = 0; $i < count($implant_data["implant_id"]); $i++):   ?>
                <tr>
                    <th scope="row"><?php $i ?></th>
                    <td><?php echo htmlspecialchars($data['implant_id'][$i]); ?></td>
                    <td><?php echo htmlspecialchars($data['os'][$i]); ?></td>
                    <td><?php echo htmlspecialchars($data['ip'][$i]); ?></td>
                    <td><?php echo htmlspecialchars($data['hostname'][$i]); ?></td>
                    <td><?php echo htmlspecialchars($data['last_seen'][$i]); ?></td>
                </tr>
            <?php endfor; ?>
        </tbody>
    </table>
    <?php else: ?>
        <p>No agent data available.</p>
    <?php endif; ?>

    </body>
</html>

<?php
session_destroy();
?>