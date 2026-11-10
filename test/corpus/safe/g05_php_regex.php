<?php
$pat = '/^[a-z0-9_-]{1,32}$/';
if (!preg_match($pat, $_GET['slug'])) { exit('bad'); }
