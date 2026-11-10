<?php
$host = $_GET['host'];
if (!preg_match('/^[a-zA-Z0-9.\-]{1,253}$/', $host)) { exit('bad'); }
system('ping -c 1 ' . escapeshellarg($host));
