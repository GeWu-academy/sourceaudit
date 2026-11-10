<?php
function t($n)
{
    $sql = <<<SQL
    SELECT * FROM logs WHERE path LIKE '/var/*/logs'
    SQL;
    system("ls " . $n);
}
