<?php
$name = $_POST['name'];
$clean = basename($_POST['other']);
file_put_contents('/var/www/u/' . $name, $data);
