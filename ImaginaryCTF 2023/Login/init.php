<?php
if (file_exists('/db.sqlite3')) {
    die();
}
$db = new SQLite3('/db.sqlite3');
$db->exec(<<<EOF
CREATE TABLE IF NOT EXISTS users (
    username TEXT NOT NULL,
    pwhash TEXT NOT NULL
);
EOF);

$users = [
    'guest' => 'guest',
    'admin' => 'jctf{red_flags_and_fake_flags_form_an_equivalence_class}'
];

foreach ($users as $username => $password) {
    $pwhash = password_hash($password, PASSWORD_DEFAULT);
    $db->exec("INSERT INTO users (username, pwhash) VALUES ('$username', '$pwhash')");
}
