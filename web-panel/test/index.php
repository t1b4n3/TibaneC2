<?php
session_start();
#require "c2.php";
#require("c2.php");

require "c2_api.php";

c2_conn();

$agent_data = '';

function main() {
    // check if user is logged in first
    #if (empty($_SESSION['login'])) {
    #if (!isset($_SESSION['login'])) {
        // go to login page
        #header("Location: ./login.php");
        #exit();
    #}   

    //$agent_data = AgentInfo();
    $agent_data = AgentInfo();
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
    <?php if (!empty($agent_data['implant_id'])): ?>
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
            <?php for ($i = 0; $i < count($agent_data["implant_id"]); $i++):   ?>
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