<?php
require_once __DIR__ . '/BlockchainImporter.php';

// Set unlimited execution time
set_time_limit(0);
ini_set('memory_limit', '1G');

$importer = new BlockchainImporter();
$importer->import();