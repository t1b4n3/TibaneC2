<?php
session_start();
#require "c2.php";
#require("c2.php");

$agent_data = '';

$json = '{
    "agent_id": ["A001", "A002"],
    "os": ["Windows", "Linux"],
    "ip": ["192.168.1.10", "192.168.1.11"],
    "mac": ["00:11:22:33:44:55", "66:77:88:99:AA:BB"],
    "hostname": ["LAPTOP-1", "KALI-BOX"],
    "last_seen": ["2025-07-01 10:00:00", "2025-07-01 10:10:00"]
  }';
  
$data = json_decode($json, true); // Decode as associative array
  

function main() {
    // check if user is logged in first
    if (empty($_SESSION['login'])) {
        // go to login page
        header("Location: ./login.php");
        exit();
    }   

    //$agent_data = AgentInfo();
    $agent_data = $data;
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
    
    <?php if (!empty($data['agent_id'])): ?>
    <table class="table">
        <thead lass="thead-dark">
            <tr>
                <th scope='col'>#</th>
                <th scope="col">Agent ID</th>
                <th scope="col">Operating System</th>
                <th scope="col">IP address</th>
                <th scope="col">MAC address</th>
                <th scope="col">Hostname</th>
                <th scope="col">Last Seen</th>
            </tr>
        </thead>
        <tbody>
            <?php for ($i = 0; $i < count($agent_data["agent_id"]); $i++):   ?>
                <tr>
                    <th scope="row"><?php $i ?></th>
                    <td><?php echo htmlspecialchars($data['agent_id'][$i]); ?></td>
                    <td><?php echo htmlspecialchars($data['os'][$i]); ?></td>
                    <td><?php echo htmlspecialchars($data['ip'][$i]); ?></td>
                    <td><?php echo htmlspecialchars($data['mac'][$i]); ?></td>
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