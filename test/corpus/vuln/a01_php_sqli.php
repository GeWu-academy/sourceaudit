<?php
$id = $_GET['id'];
$q = "SELECT * FROM users WHERE id = $id";
$r = mysqli_query($conn, $q);
