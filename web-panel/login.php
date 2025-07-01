<?php 



function main() {
    if (authenticate($_POST['username'], $_POST_['password']) == 0) {
        $_SESSION['login'] = $_POST['username'];
        // sign in 
    }  else {
        // failed to authenticate (wrong creds)
    }
}

?>


<!DOCTYPE html>
<html>
<head></head>
    <body>
        <form method='post'>
            <label><input name='username' type='text' required><br>
            <labeL><input name='password' type='password' required><br>
            <button type='submit' name='log-in'>Log IN</button>
        </form>
    </body>
</html>

<?php
if (isset($_POST['log-in'])) {
    main();
}
?>