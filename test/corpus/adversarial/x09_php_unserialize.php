<?php
$c = $_COOKIE['prefs'];
$prefs = unserialize(base64_decode($c));
echo $prefs['theme'];
