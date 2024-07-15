<?php
$sec = intval($_GET['seconds']);
sleep($sec);
echo 'OK';
