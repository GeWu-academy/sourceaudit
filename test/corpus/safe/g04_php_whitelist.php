<?php
$map = ['home' => 'home.php', 'about' => 'about.php'];
$p = $_GET['page'] ?? 'home';
if (!isset($map[$p])) { exit('bad'); }
include __DIR__ . '/' . $map[$p];
