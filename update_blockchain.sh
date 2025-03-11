#!/bin/bash
PHP_BIN=/usr/bin/php
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Run the blockchain importer
$PHP_BIN $SCRIPT_DIR/import_blockchain.php >> $SCRIPT_DIR/import.log 2>&1