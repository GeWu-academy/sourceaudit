<?php
$root = realpath('/var/www/files');
$f = basename($_GET['file']);
$real = realpath($root . DIRECTORY_SEPARATOR . $f);
if ($real === false || strpos($real, $root . DIRECTORY_SEPARATOR) !== 0) {
    http_response_code(403);
    exit;
}
readfile($real);
