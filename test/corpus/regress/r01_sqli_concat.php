<?php
$sql = "SELECT * FROM users WHERE name = '" . $_GET['n'] . "'";
$r = $pdo->query($sql);
