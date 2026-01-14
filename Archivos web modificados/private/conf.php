<?php
if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'])) {
    http_response_code(403);
    exit('Forbidden');
}

$db = new SQLite3(dirname(__FILE__) . "/database.db") or die ("Unable to open database");
?>
