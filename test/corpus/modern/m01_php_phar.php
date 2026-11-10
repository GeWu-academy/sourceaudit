<?php
// phar 反序列化 + 客户端文件名落盘 + 可变变量覆盖
$tpl = $_GET['tpl'];
include 'phar://' . $tpl . '/payload.txt';
$name = $_FILES['f']['name'];
file_put_contents('/var/www/uploads/' . $name, 'x');
$k = $_GET['k'];
$$k = 1;
