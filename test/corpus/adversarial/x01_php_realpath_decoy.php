<?php
$f = $_GET['f'];
$p = realpath($f);
readfile($f);
