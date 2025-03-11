<?php
// Configure session handling before starting the session
ini_set('session.save_handler', 'files');
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Check if config file exists
$configFile = __DIR__ . '/importer.conf';
if (!file_exists($configFile)) {
    die("Configuration file not found");
}

// Get admin password and database settings from config
$config = parse_ini_file($configFile);
if (!$config || !isset($config['ADMIN_PASSWORD']) || 
    !isset($config['DB_HOST']) || !isset($config['DB_NAME']) || 
    !isset($config['DB_USER']) || !isset($config['DB_PASS'])) {
    die("Invalid configuration file");
}

$storedHash = trim($config['ADMIN_PASSWORD'], '"');

// Handle login
if (isset($_POST['admin_password'])) {
    if (password_verify($_POST['admin_password'], $storedHash)) {
        $_SESSION['master_reset_auth'] = true;
    } else {
        $error = "Invalid password";
    }
}

// Handle AJAX reset request
$isAjax = isset($_SERVER['HTTP_X_REQUESTED_WITH']) && 
          strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest';

if ($isAjax && isset($_POST['confirm_reset']) && isset($_SESSION['master_reset_auth'])) {
    try {
        // Kill any running PHP processes related to the importer
        $processFiles = glob(__DIR__ . '/*.lock');
        foreach ($processFiles as $file) {
            @unlink($file);
        }
        
        // Wait briefly for processes to notice lock files are gone
        sleep(1);
        
        // Connect to database directly
        $dsn = "mysql:host={$config['DB_HOST']};dbname={$config['DB_NAME']};charset=utf8mb4";
        $db = new PDO($dsn, $config['DB_USER'], $config['DB_PASS'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
        ]);
        
        // Temporarily disable foreign key checks
        $db->exec("SET FOREIGN_KEY_CHECKS = 0");
        
        // Drop tables in correct order (children first, then parents)
        $tables = [
            'import_progress',    // No dependencies
            'address_balances',   // No dependencies
            'tx_inputs',          // Depends on transactions
            'tx_outputs',         // Depends on transactions
            'transactions',       // Depends on blocks
            'blocks'             // No dependencies, but referenced by transactions
        ];
        
        foreach ($tables as $table) {
            $db->exec("DROP TABLE IF EXISTS `$table`");
        }
        
        // Re-enable foreign key checks
        $db->exec("SET FOREIGN_KEY_CHECKS = 1");
        
        // Delete config and lock files
        $filesToDelete = [
            __DIR__ . '/importer.conf',
            __DIR__ . '/import.lock',
            __DIR__ . '/*.lock'  // This will be used in glob()
        ];
        
        foreach ($filesToDelete as $pattern) {
            if (strpos($pattern, '*') !== false) {
                // Handle wildcard patterns
                $files = glob($pattern);
                foreach ($files as $file) {
                    @unlink($file);
                }
            } else if (file_exists($pattern)) {
                @unlink($pattern);
            }
        }
        
        // Clear all session data
        session_destroy();
        
        echo json_encode(['success' => true]);
        exit;
        
    } catch (Exception $e) {
        error_log("Master reset error: " . $e->getMessage());
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage()
        ]);
        exit;
    }
}

// Show login form if not authenticated
if (!isset($_SESSION['master_reset_auth'])) {
    ?>
    <!DOCTYPE html>
    <html lang="en" data-bs-theme="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Master Reset Authentication</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-dark text-light">
        <div class="container py-5">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="card bg-dark border-danger">
                        <div class="card-header border-danger">
                            <h4 class="mb-0 text-danger">⚠️ Master Reset Authentication</h4>
                        </div>
                        <div class="card-body">
                            <?php if (isset($error)): ?>
                                <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
                            <?php endif; ?>
                            <form method="POST">
                                <div class="mb-3">
                                    <label for="admin_password" class="form-label">Admin Password</label>
                                    <input type="password" class="form-control bg-dark text-light" 
                                           id="admin_password" name="admin_password" required autofocus>
                                </div>
                                <div class="d-flex justify-content-between">
                                    <a href="import_blockchain_web.php" class="btn btn-secondary">Cancel</a>
                                    <button type="submit" class="btn btn-danger">Authenticate</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    <?php
    exit;
}

// If we get here, user is authenticated - show reset confirmation page
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Master Reset - Blockchain Import</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark text-light">
    <div class="container py-5">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card bg-danger text-white">
                    <div class="card-header">
                        <h4 class="mb-0">⚠️ Master Reset</h4>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-warning">
                            <strong>WARNING:</strong> This will delete ALL data and reset EVERYTHING to initial state.
                            <hr>
                            This includes:
                            <ul>
                                <li>Dropping all database tables</li>
                                <li>Deleting configuration files</li>
                                <li>Clearing all settings and locks</li>
                                <li>Removing all import progress</li>
                            </ul>
                            <strong>This action CANNOT be undone!</strong>
                        </div>
                        
                        <div class="d-flex justify-content-between align-items-center">
                            <a href="import_blockchain_web.php" class="btn btn-light">Cancel</a>
                            <button type="button" id="confirmResetBtn" class="btn btn-warning">
                                <span class="spinner-border spinner-border-sm d-none" role="status" aria-hidden="true"></span>
                                Confirm Reset
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        document.getElementById('confirmResetBtn').addEventListener('click', async function() {
            if (!confirm('Are you absolutely sure you want to proceed with the master reset?')) {
                return;
            }
            
            const button = this;
            const spinner = button.querySelector('.spinner-border');
            
            button.disabled = true;
            spinner.classList.remove('d-none');
            
            try {
                const response = await fetch('master_reset.php', {
                    method: 'POST',
                    headers: { 
                        'X-Requested-With': 'XMLHttpRequest',
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: 'confirm_reset=1'
                });

                const result = await response.json();
                
                if (!response.ok) {
                    throw new Error(result.error || `Server error: ${response.status}`);
                }
                
                if (!result.success) {
                    throw new Error(result.error || 'Reset failed');
                }

                alert('Reset successful. You will now be redirected to the setup page.');
                window.location.href = 'import_blockchain_web.php';
                
            } catch (error) {
                console.error('Error performing master reset:', error);
                alert('Failed to perform master reset: ' + error.message);
                button.disabled = false;
                spinner.classList.add('d-none');
            }
        });
    </script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>