<?php

if (isset($_GET['source'])) {
    highlight_file(__FILE__);
    die();
}

$flag = $_ENV['FLAG'] ?? 'jctf{test_flag}';
$magic = $_ENV['MAGIC'] ?? 'aabbccdd11223344';
$db = new SQLite3('/db.sqlite3');

$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';
$msg = '';

if (isset($_GET[$magic])) {
    $password .= $flag;
}

if ($username && $password) {
    $res = $db->querySingle("SELECT username, pwhash FROM users WHERE username = '$username'", true);
    if (!$res) {
        $msg = "Invalid username or password";
    } else if (password_verify($password, $res['pwhash'])) {
        $u = htmlentities($res['username']);
        $msg = "Welcome $u! But there is no flag here :P";
        if ($res['username'] === 'admin') {
            $msg .= "<!-- magic: $magic -->";
        }
    } else {
        $msg = "Invalid username or password";
    }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Login</title>
    <link type="text/css" rel="stylesheet" href="https://cdn.simplecss.org/simple.css" />
</head>

<body>
    <main>
        <h2>Login</h2>
        <form method="POST">
            <p>
                <label for="username">Username</label>
                <input type="text" name="username" placeholder="Username" />
            </p>
            <p>
                <label for="password">Password</label>
                <input type="password" name="password" placeholder="Password" />
            </p>
            <p>
                <button type="submit">Login</button>
            </p>
        </form>
        <p>
            <?= $msg ?>
        </p>
    </main>
</body>

</html>
<!-- /?source -->