<?php
$expr = $_GET['e'];
$out = eval("return $expr;");
echo $out;
