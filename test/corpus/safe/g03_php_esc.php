<?php
echo "<h1>Hello " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') . "</h1>";
