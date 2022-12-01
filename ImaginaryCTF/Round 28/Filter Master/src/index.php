<?php
if (isset($_GET['info'])) {
    phpinfo();
    die();
}
if (isset($_POST['filter'])) {
    $filter = $_POST['filter'];
    if (strstr($filter, '/')) {
        die('???');
    }
    $result = file_get_contents("php://filter/$filter/resource=/dev/null");
    if ($result === 'plz give me the flag') {
        echo file_get_contents('/flag.txt');
    } else {
        echo 'You got: ' . htmlspecialchars($result);
    }
} else {
    highlight_file(__FILE__);
}
?>
<form action="." method="POST">
    <textarea name="filter"></textarea>
    <button type="submit">Submit</button>
</form>