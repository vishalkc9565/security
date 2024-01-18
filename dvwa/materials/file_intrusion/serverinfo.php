<?php
// Retrieve server information
$serverInfo = $_SERVER['SERVER_SOFTWARE'];

// Retrieve PHP version
$phpVersion = phpversion();

// Output server information and PHP version
echo "Server Information: " . $serverInfo . "<br>";
echo "PHP Version: " . $phpVersion;
?>
