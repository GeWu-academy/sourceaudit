<?php
$prefs = json_decode($_COOKIE['prefs'] ?? '{}', true);
if (!is_array($prefs)) { $prefs = []; }
