<?php
ini_set('max_execution_time', '0');     // Remove PHP timeout limit
set_time_limit(0);                      // Alternative method for some systems
ini_set('memory_limit', '1G');          // Increase memory limit if need

if (!defined('IN_SCRIPT')) {
    define("IN_SCRIPT", true);
}

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/libs/BitcoinRPC.php'; // Updated path
require_once __DIR__ . '/libs/functions.php';

class BlockchainImporter {
    private $rpc;
    private $db;
    private $lastProcessedHeight = -1;
    private $maxBlocksPerRun = 1000;
    private $blockDelay = 0;
    private $maxRpcBatchSize = 100; // Reduced default batch size
    private $blockCache = [];

    public function __construct() {
        $config = Config::getInstance();
        
        $this->rpc = new BitcoinRPC(
            $config->get('RPC_USER'),
            $config->get('RPC_PASSWORD'),
            $config->get('RPC_HOST'),
            (int)$config->get('RPC_PORT')
        );
        
        // Set longer timeouts for larger batch requests
        $this->rpc->setTimeouts(120, 300); // 2 minutes connection, 5 minutes request
        
        try {
            // Initialize database connection using PDO with optimized settings
            $this->db = new PDO(
                "mysql:host=" . $config->get('DB_HOST') . ";dbname=" . $config->get('DB_NAME'),
                $config->get('DB_USER'),
                trim($config->get('DB_PASS'), '"'), // Remove quotes from the password
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_AUTOCOMMIT => false,
                    PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => false,
                    PDO::ATTR_EMULATE_PREPARES => false,
                    PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4, SESSION innodb_lock_wait_timeout=30",
                    PDO::ATTR_PERSISTENT => true
                ]
            );
            
            // Create blocks table if it doesn't exist
            $this->initializeDatabase();
            
            // Get last processed block from database
            $stmt = $this->db->query("SELECT MAX(height) as height FROM blocks");
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            $this->lastProcessedHeight = $result['height'] !== null ? (int)$result['height'] : -1;
            
        } catch (PDOException $e) {
            throw new Exception("Database connection failed: " . $e->getMessage());
        }
    }

    public function setMaxBlocksPerRun($blocks) {
        $blocks = (int)$blocks;
        if ($blocks >= 100 && $blocks <= 10000) {
            $this->maxBlocksPerRun = $blocks;
        }
        return $this;
    }

    public function setBlockDelay($delay) {
        $delay = (int)$delay;
        if ($delay >= 0 && $delay <= 1000) {
            $this->blockDelay = $delay;
        }
        return $this;
    }

    public function setMaxRpcBatchSize($size) {
        $this->maxRpcBatchSize = max(1, min(100, (int)$size));
        return $this;
    }

    private function initializeDatabase() {
        // Create blocks table
        $this->db->exec("CREATE TABLE IF NOT EXISTS blocks (
            height INT NOT NULL,
            hash VARCHAR(64) NOT NULL,
            previousblockhash VARCHAR(64) NULL,
            merkle_root VARCHAR(64) NOT NULL,
            time INT NOT NULL,
            bits VARCHAR(8) NOT NULL,
            nonce BIGINT NOT NULL,
            size INT NOT NULL,
            version INT NOT NULL,
            difficulty DECIMAL(20,8) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (height),
            KEY idx_hash (hash)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // Create transactions table
        $this->db->exec("CREATE TABLE IF NOT EXISTS transactions (
            txid VARCHAR(64) NOT NULL,
            block_height INT NOT NULL,
            block_hash VARCHAR(64) NOT NULL,
            time INT NOT NULL,
            size INT NOT NULL,
            version INT NOT NULL,
            locktime INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (txid),
            KEY idx_block_height (block_height),
            KEY idx_block_hash (block_hash),
            CONSTRAINT fk_tx_block FOREIGN KEY (block_height) REFERENCES blocks(height)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // Create transaction inputs table
        $this->db->exec("CREATE TABLE IF NOT EXISTS tx_inputs (
            id BIGINT AUTO_INCREMENT,
            txid VARCHAR(64) NOT NULL,
            vout INT NOT NULL,
            prev_txid VARCHAR(64) NULL,
            prev_vout INT NULL,
            scriptsig TEXT NULL,
            sequence BIGINT NOT NULL,
            witness TEXT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_txid (txid),
            KEY idx_prev_txid (prev_txid),
            CONSTRAINT fk_input_tx FOREIGN KEY (txid) REFERENCES transactions(txid)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // Create transaction outputs table
        $this->db->exec("CREATE TABLE IF NOT EXISTS tx_outputs (
            id BIGINT AUTO_INCREMENT,
            txid VARCHAR(64) NOT NULL,
            vout INT NOT NULL,
            value DECIMAL(18,8) NOT NULL,
            scriptpubkey TEXT NOT NULL,
            scriptpubkey_type VARCHAR(32) NULL,
            scriptpubkey_address VARCHAR(100) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY idx_txid_vout (txid, vout),
            CONSTRAINT fk_output_tx FOREIGN KEY (txid) REFERENCES transactions(txid)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // Create address balance table
        $this->db->exec("CREATE TABLE IF NOT EXISTS address_balances (
            address VARCHAR(100) NOT NULL,
            balance DECIMAL(65,8) NOT NULL DEFAULT 0,
            received DECIMAL(65,8) NOT NULL DEFAULT 0,
            sent DECIMAL(65,8) NOT NULL DEFAULT 0,
            first_tx_time INT NULL,
            last_tx_time INT NULL,
            tx_count INT NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (address)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // Modify tx_outputs table to handle larger values
        $this->db->exec("ALTER TABLE tx_outputs 
            MODIFY value DECIMAL(65,8) NOT NULL");

        // Modify address_balances table to handle larger values
        $this->db->exec("ALTER TABLE address_balances 
            MODIFY balance DECIMAL(65,8) NOT NULL DEFAULT 0,
            MODIFY received DECIMAL(65,8) NOT NULL DEFAULT 0,
            MODIFY sent DECIMAL(65,8) NOT NULL DEFAULT 0");
    }

    private function prefetchBlockBatch($startHeight, $endHeight) {
        $this->blockCache = [];
        $batchSize = $this->maxRpcBatchSize;
        
        for ($currentHeight = $startHeight; $currentHeight <= $endHeight; $currentHeight += $batchSize) {
            $endBatchHeight = min($currentHeight + $batchSize - 1, $endHeight);
            
            // Get block hashes
            $this->rpc->clearBatch();
            for ($height = $currentHeight; $height <= $endBatchHeight; $height++) {
                $this->rpc->addToBatch('getblockhash', [$height]);
            }
            
            $hashes = $this->rpc->executeBatch();
            
            // Get block data
            $this->rpc->clearBatch();
            foreach ($hashes as $index => $hash) {
                $this->rpc->addToBatch('getblock', [$hash, 2]);
            }
            
            $blocks = $this->rpc->executeBatch();
            foreach ($blocks as $index => $block) {
                $this->blockCache[$currentHeight + $index] = $block;
            }
            
            if ($this->blockDelay > 0) {
                usleep($this->blockDelay * 1000);
            }
        }
    }

    private function importBlockBatch($startHeight, $endHeight) {
        $this->db->beginTransaction();
        try {
            // Collect values for bulk insert
            $blockValues = [];
            $txValues = [];
            $placeholders = [];

            for ($height = $startHeight; $height <= $endHeight; $height++) {
                $block = $this->blockCache[$height] ?? null;
                if (!$block) continue;

                // Collect block data
                $blockValues[] = $height;
                $blockValues[] = $block['hash'];
                $blockValues[] = $block['previousblockhash'] ?? null;
                $blockValues[] = $block['merkleroot'];
                $blockValues[] = $block['time'];
                $blockValues[] = $block['bits'];
                $blockValues[] = $block['nonce'];
                $blockValues[] = $block['size'];
                $blockValues[] = $block['version'];
                $blockValues[] = $block['difficulty'];
                
                $placeholders[] = "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

                // Collect transaction data
                foreach ($block['tx'] as $tx) {
                    $txValues[] = $tx['txid'];
                    $txValues[] = $height;
                    $txValues[] = $block['hash'];
                    $txValues[] = $block['time'];
                    $txValues[] = $tx['size'];
                    $txValues[] = $tx['version'];
                    $txValues[] = $tx['locktime'];
                }
            }

            // Bulk insert blocks
            if (!empty($blockValues)) {
                $sql = "INSERT INTO blocks (height, hash, previousblockhash, merkle_root, time, bits, nonce, size, version, difficulty) 
                       VALUES " . implode(',', $placeholders);
                $stmt = $this->db->prepare($sql);
                $stmt->execute($blockValues);
            }

            // Bulk insert transactions in chunks
            $chunkSize = 1000; // Adjust based on testing
            $txChunks = array_chunk($txValues, $chunkSize * 7); // 7 fields per transaction

            foreach ($txChunks as $chunk) {
                $placeholders = array_fill(0, count($chunk) / 7, "(?, ?, ?, ?, ?, ?, ?)");
                $sql = "INSERT INTO transactions (txid, block_height, block_hash, time, size, version, locktime) 
                       VALUES " . implode(',', $placeholders);
                $stmt = $this->db->prepare($sql);
                $stmt->execute($chunk);

                if ($this->blockDelay > 0) {
                    usleep($this->blockDelay * 1000);
                }
            }

            $this->db->commit();
        } catch (Exception $e) {
            $this->db->rollBack();
            throw $e;
        }
    }

    private function cleanupOldCache($currentHeight) {
        // Keep a window of blocks for potential reorgs
        $cacheWindow = 10; // Adjust based on your needs
        
        // Only cleanup blocks that are well behind the current height
        $cleanupHeight = $currentHeight - $cacheWindow;
        
        if ($cleanupHeight > 0) {
            foreach ($this->blockCache as $height => $block) {
                if ($height < $cleanupHeight) {
                    unset($this->blockCache[$height]);
                }
            }
        }
    }

    public function import() {
        try {
            $info = $this->rpc->getblockchaininfo();
            if ($this->rpc->status !== 200) {
                throw new Exception("Failed to get blockchain info: " . $this->rpc->error);
            }

            $currentHeight = $info['blocks'];
            $startHeight = $this->lastProcessedHeight + 1;
            $blocksToProcess = min($this->maxBlocksPerRun, $currentHeight - $startHeight + 1);

            if ($blocksToProcess <= 0) {
                return [
                    'status' => 'up_to_date',
                    'height' => $currentHeight
                ];
            }

            $endHeight = $startHeight + $blocksToProcess - 1;

            // Prefetch the entire batch
            $this->prefetchBlockBatch($startHeight, $endHeight);
            
            // Import the batch
            $this->importBlockBatch($startHeight, $endHeight);

            $this->lastProcessedHeight = $endHeight;

            // Add periodic cache cleanup
            if ($this->lastProcessedHeight % 10000 === 0) { // Every 100 blocks
                $this->cleanupOldCache($this->lastProcessedHeight);
            }

            return [
                'status' => 'importing',
                'start_height' => $startHeight,
                'end_height' => $endHeight,
                'current_height' => $currentHeight,
                'progress' => ($endHeight / $currentHeight) * 100
            ];

        } catch (Exception $e) {
            error_log("Import failed: " . $e->getMessage());
            throw $e;
        }
    }

    private function importBlockTransactions($block) {
        if (!isset($block['tx']) || !is_array($block['tx'])) {
            error_log("No transactions found in block " . $block['height']);
            return;
        }

        foreach ($block['tx'] as $tx) {
            try {
                // Transaction data is already in the block data when verbosity=2
                // No need to call getrawtransaction again
                if (!is_array($tx)) {
                    error_log("Invalid transaction data in block " . $block['height']);
                    continue;
                }

                // Insert transaction
                $stmt = $this->db->prepare("INSERT INTO transactions 
                    (txid, block_height, block_hash, time, size, version, locktime) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)");
                
                $stmt->execute([
                    $tx['txid'],
                    $block['height'],
                    $block['hash'],
                    $block['time'], // Use block time since not all transactions have their own timestamp
                    $tx['size'],
                    $tx['version'],
                    $tx['locktime']
                ]);

                // Insert inputs
                if (isset($tx['vin']) && is_array($tx['vin'])) {
                    foreach ($tx['vin'] as $vin) {
                        // Skip coinbase inputs
                        if (isset($vin['coinbase'])) {
                            continue;
                        }

                        $stmt = $this->db->prepare("INSERT INTO tx_inputs 
                            (txid, vout, prev_txid, prev_vout, scriptsig, sequence, witness) 
                            VALUES (?, ?, ?, ?, ?, ?, ?)");
                        
                        $stmt->execute([
                            $tx['txid'],
                            $vin['vout'] ?? 0,
                            $vin['txid'] ?? null,
                            $vin['vout'] ?? null,
                            $vin['scriptSig']['hex'] ?? null,
                            $vin['sequence'],
                            isset($vin['txinwitness']) ? json_encode($vin['txinwitness']) : null
                        ]);
                    }
                }

                // Insert outputs
                if (isset($tx['vout']) && is_array($tx['vout'])) {
                    foreach ($tx['vout'] as $vout) {
                        $stmt = $this->db->prepare("INSERT INTO tx_outputs 
                            (txid, vout, value, scriptpubkey, scriptpubkey_type, scriptpubkey_address) 
                            VALUES (?, ?, ?, ?, ?, ?)");
                        
                        $address = null;
                        if (isset($vout['scriptPubKey']['addresses']) && is_array($vout['scriptPubKey']['addresses'])) {
                            $address = $vout['scriptPubKey']['addresses'][0];
                        }
                        
                        $value = $vout['value'];
                        
                        // Validate value before insertion
                        if (!is_numeric($value) || $value < 0 || $value > 1e57) { // Max safe value for DECIMAL(65,8)
                            error_log("Invalid transaction value in block {$block['height']}, tx {$tx['txid']}: $value");
                            throw new Exception("Transaction value out of range: $value");
                        }

                        $stmt->execute([
                            $tx['txid'],
                            $vout['n'],
                            $value,
                            $vout['scriptPubKey']['hex'],
                            $vout['scriptPubKey']['type'] ?? null,
                            $address
                        ]);

                        // Update address balance
                        if ($address !== null) {
                            $stmt = $this->db->prepare("INSERT INTO address_balances 
                                (address, balance, received, tx_count, first_tx_time, last_tx_time) 
                                VALUES (?, ?, ?, 1, ?, ?)
                                ON DUPLICATE KEY UPDATE 
                                balance = balance + ?,
                                received = received + ?,
                                tx_count = tx_count + 1,
                                last_tx_time = GREATEST(last_tx_time, ?)");
                            
                            $stmt->execute([
                                $address,
                                $value,
                                $value,
                                $block['time'],
                                $block['time'],
                                $value,
                                $value,
                                $block['time']
                            ]);
                        }
                    }
                }

            } catch (Exception $e) {
                error_log("Error processing transaction in block " . $block['height'] . ": " . $e->getMessage());
                throw $e; // Re-throw to stop the import process
            }
        }
    }

    public function getStatus() {
        try {
            // Get blockchain info with error handling
            $info = $this->rpc->getblockchaininfo();
            
            // Ensure we have a valid response
            if (!is_array($info)) {
                throw new Exception("Invalid blockchain info response");
            }

            // Get database status
            $stmt = $this->db->query("SELECT COUNT(*) as count, MAX(height) as height FROM blocks");
            $dbStatus = $stmt->fetch(PDO::FETCH_ASSOC);

            // Extract required fields with fallbacks
            $blocks = isset($info['blocks']) ? (int)$info['blocks'] : 0;
            $headers = isset($info['headers']) ? (int)$info['headers'] : 0;
            $difficulty = isset($info['difficulty']) ? (float)$info['difficulty'] : 0;
            $chain = $info['chain'] ?? 'main';
            $verificationProgress = isset($info['verificationprogress']) ? (float)$info['verificationprogress'] : 0;

            $lastImportedHeight = ($dbStatus['height'] !== null) ? (int)$dbStatus['height'] : -1;
            $importedBlocks = ($dbStatus['count'] !== null) ? (int)$dbStatus['count'] : 0;

            return [
                'current_height' => $blocks,
                'headers' => $headers,
                'difficulty' => $difficulty,
                'chain' => $chain,
                'verification_progress' => $verificationProgress,
                'imported_blocks' => $importedBlocks,
                'last_imported_height' => $lastImportedHeight,
                'import_progress' => ($blocks > 0) ? 
                    (($lastImportedHeight + 1) / ($blocks + 1)) * 100 : 0
            ];
        } catch (Exception $e) {
            error_log("GetStatus error: " . $e->getMessage());
            throw new Exception("Failed to get status: " . $e->getMessage());
        }
    }

    public function resetDatabase() {
        try {
            // First, try to remove any lock files that might exist
            $lockFile = __DIR__ . '/importer.lock';
            if (file_exists($lockFile)) {
                @unlink($lockFile);
            }

            // Store all connection info before doing anything else
            $connectionInfo = [
                'host' => $this->db->query("SELECT @@hostname")->fetchColumn(),
                'dbname' => $this->db->query("SELECT DATABASE()")->fetchColumn(),
                'user' => $this->db->query("SELECT CURRENT_USER()")->fetchColumn(),
                'processId' => $this->db->query("SELECT CONNECTION_ID()")->fetchColumn()
            ];

            // Get current database credentials from config file
            $configFile = __DIR__ . '/importer.conf';
            if (!file_exists($configFile)) {
                throw new Exception("Configuration file not found");
            }
            $config = parse_ini_file($configFile);
            $dbPassword = trim($config['DB_PASS'], '"');
            
            // Use buffered query for process list
            $stmt = $this->db->prepare("
                SELECT ID 
                FROM information_schema.PROCESSLIST 
                WHERE DB = ? 
                AND ID != ?"
            );
            $stmt->execute([$connectionInfo['dbname'], $connectionInfo['processId']]);
            $processes = $stmt->fetchAll(PDO::FETCH_COLUMN);
            
            // Kill other connections, ignoring errors for already closed connections
            foreach ($processes as $pid) {
                try {
                    $this->db->exec("KILL CONNECTION $pid");
                    $this->db->exec("KILL QUERY $pid");
                } catch (PDOException $e) {
                    // Ignore "Unknown thread id" errors
                    if (strpos($e->getMessage(), 'Unknown thread id') === false) {
                        error_log("Error killing process $pid: " . $e->getMessage());
                    }
                }
            }

            // Wait a moment for connections to close
            sleep(1);
            
            // Close current connection
            $this->db = null;
            
            // Reopen connection with buffered queries enabled
            $this->db = new PDO(
                "mysql:host={$connectionInfo['host']};dbname={$connectionInfo['dbname']}",
                $connectionInfo['user'],
                $dbPassword,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_PERSISTENT => false,
                    PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => true
                ]
            );

            // Disable any running events
            $this->db->exec("SET GLOBAL event_scheduler = OFF");
            
            try {
                $this->db->exec("FLUSH TABLES WITH READ LOCK");
                $this->db->exec("FLUSH HOSTS");
            } catch (PDOException $e) {
                error_log("Failed to flush tables: " . $e->getMessage());
            }

            try {
                // Drop all tables with foreign key checks disabled
                $this->db->exec("SET FOREIGN_KEY_CHECKS = 0");
                
                // Get all tables in the database
                $stmt = $this->db->query("
                    SELECT TABLE_NAME 
                    FROM information_schema.TABLES 
                    WHERE TABLE_SCHEMA = '{$connectionInfo['dbname']}'"
                );
                $tables = $stmt->fetchAll(PDO::FETCH_COLUMN);
                
                // Drop each table
                foreach ($tables as $tableName) {
                    $this->db->exec("DROP TABLE IF EXISTS `$tableName`");
                }
                
                $this->db->exec("SET FOREIGN_KEY_CHECKS = 1");
            } finally {
                // Make sure to unlock tables even if drop fails
                $this->db->exec("UNLOCK TABLES");
            }

            // Re-enable event scheduler
            $this->db->exec("SET GLOBAL event_scheduler = ON");
            
            // Re-initialize the database structure
            $this->initializeDatabase();
            
            return true;
        } catch (PDOException $e) {
            throw new Exception("Failed to reset database: " . $e->getMessage());
        }
    }
}
