<?php
$f = $_GET['file'];
readfile("/var/www/" . $f);
