<?php
$allow = ['image/png' => 'png', 'image/jpeg' => 'jpg'];
$fi = new finfo(FILEINFO_MIME_TYPE);
$mime = $fi->file($_FILES['f']['tmp_name']);
if (!isset($allow[$mime])) { exit('bad type'); }
$name = bin2hex(random_bytes(16)) . '.' . $allow[$mime];
move_uploaded_file($_FILES['f']['tmp_name'], '/var/www/uploads/' . $name);
