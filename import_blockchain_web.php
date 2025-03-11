<?php
/**
 * Blockchain Import Web Interface
 * 
 * Provides a web-based interface for monitoring and controlling the blockchain import process.
 * Features include authentication, real-time progress monitoring, import speed tracking,
 * and process locking to prevent concurrent imports.
 */

// Disable error reporting
error_reporting(0);
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);

// At the top of the file, after the initial setup
ini_set('max_execution_time', 0);     // Remove PHP timeout limit
set_time_limit(0);                    // Alternative method for some systems
ini_set('memory_limit', '1G');        // Increase memory limit if needed

define("IN_SCRIPT", true);
define('LOCK_FILE', __DIR__ . '/import.lock');  // Lock file to prevent concurrent imports
require_once __DIR__ . '/config.php';

// Check configuration before attempting to use it
$config = Config::getInstance();
if (!$config->isConfigured() && !isset($_POST['create_config'])) {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Blockchain Importer Setup</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="assets/styles.css" rel="stylesheet">
        <style>
            :root {
                color-scheme: dark;
                --bs-body-color: #dee2e6;
                --bs-body-bg: #212529;
            }
            body {
                background-color: var(--bs-body-bg);
                color: var(--bs-body-color);
            }
            .card {
                background-color: #2c3338;
                border-color: #444;
            }
            .form-control {
                background-color: #1a1a1a;
                border-color: #444;
                color: #dee2e6;
            }
            .form-control:focus {
                background-color: #1a1a1a;
                border-color: #666;
                color: #dee2e6;
            }
        </style>
    </head>
    <body>
        <div class="container mt-5">
            <div class="row justify-content-center">
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">Initial Configuration Required</h4>
                        </div>
                        <div class="card-body">
                            <form method="POST" id="configForm">
                                <!-- Database Configuration -->
                                <div class="mb-4">
                                    <h5 class="mb-3">Database Configuration</h5>
                                    <div class="mb-3">
                                        <label for="db_host" class="form-label">Database Host</label>
                                        <input type="text" class="form-control" id="db_host" name="db_host" value="localhost" required>
                                    </div>
                                    <div class="mb-3">
                                        <label for="db_name" class="form-label">Database Name</label>
                                        <input type="text" class="form-control" id="db_name" name="db_name" required>
                                    </div>
                                    <div class="mb-3">
                                        <label for="db_user" class="form-label">Database User</label>
                                        <input type="text" class="form-control" id="db_user" name="db_user" required>
                                    </div>
                                    <div class="mb-3">
                                        <label for="db_pass" class="form-label">Database Password</label>
                                        <input type="password" class="form-control" id="db_pass" name="db_pass" required>
                                    </div>
                                </div>

                                <!-- RPC Configuration -->
                                <div class="mb-4">
                                    <h5 class="mb-3">RPC Configuration</h5>
                                    <div class="mb-3">
                                        <label for="rpc_host" class="form-label">RPC Host</label>
                                        <input type="text" class="form-control" id="rpc_host" name="rpc_host" value="127.0.0.1" required>
                                    </div>
                                    <div class="mb-3">
                                        <label for="rpc_port" class="form-label">RPC Port</label>
                                        <input type="number" class="form-control" id="rpc_port" name="rpc_port" value="8333" required>
                                    </div>
                                    <div class="mb-3">
                                        <label for="rpc_user" class="form-label">RPC Username</label>
                                        <input type="text" class="form-control" id="rpc_user" name="rpc_user" required>
                                    </div>
                                    <div class="mb-3">
                                        <label for="rpc_pass" class="form-label">RPC Password</label>
                                        <input type="password" class="form-control" id="rpc_pass" name="rpc_pass" required>
                                    </div>
                                </div>

                                <!-- Admin Configuration -->
                                <div class="mb-4">
                                    <h5 class="mb-3">Admin Configuration</h5>
                                    <div class="mb-3">
                                        <label for="admin_pass" class="form-label">Admin Password</label>
                                        <input type="password" class="form-control" id="admin_pass" name="admin_pass" 
                                               pattern="^(?=.*[A-Z].*[A-Z])(?=.*[!@#$%^&*])(?=.*[0-9])(?=.*[a-z]).{8,}$"
                                               required>
                                        <div class="form-text text-light">
                                            Password must contain:
                                            <ul class="mb-0">
                                                <li>Minimum 8 characters</li>
                                                <li>At least 2 capital letters</li>
                                                <li>At least 1 special character (!@#$%^&*)</li>
                                                <li>At least 1 number</li>
                                                <li>At least 1 lowercase letter</li>
                                            </ul>
                                        </div>
                                        <div id="passwordFeedback" class="invalid-feedback"></div>
                                    </div>
                                </div>

                                <input type="hidden" name="create_config" value="1">
                                <button type="submit" class="btn btn-primary" id="submitBtn">Save Configuration</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            document.getElementById('configForm').addEventListener('submit', function(e) {
                const adminPass = document.getElementById('admin_pass');
                const passwordFeedback = document.getElementById('passwordFeedback');
                const passwordRegex = /^(?=.*[A-Z].*[A-Z])(?=.*[!@#$%^&*])(?=.*[0-9])(?=.*[a-z]).{8,}$/;

                if (!passwordRegex.test(adminPass.value)) {
                    e.preventDefault();
                    adminPass.classList.add('is-invalid');
                    passwordFeedback.textContent = 'Password does not meet the requirements';
                    return;
                }

                const submitBtn = document.getElementById('submitBtn');
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Saving...';
            });

            // Real-time password validation
            document.getElementById('admin_pass').addEventListener('input', function(e) {
                const password = e.target.value;
                const requirements = {
                    length: password.length >= 8,
                    capitals: (password.match(/[A-Z]/g) || []).length >= 2,
                    special: /[!@#$%^&*]/.test(password),
                    number: /[0-9]/.test(password),
                    lowercase: /[a-z]/.test(password)
                };

                // Update validation state
                if (Object.values(requirements).every(Boolean)) {
                    e.target.classList.remove('is-invalid');
                    e.target.classList.add('is-valid');
                } else {
                    e.target.classList.remove('is-valid');
                    e.target.classList.add('is-invalid');
                }
            });
        </script>
    </body>
    </html>
    <?php
    exit;
}

function checkConfigFile() {
    $configPath = __DIR__ . '/importer.conf';
    if (!file_exists($configPath) || filesize($configPath) === 0) {
        return false;
    }
    return true;
}

// Handle form submission
if (isset($_POST['create_config'])) {
    try {
        // Validate admin password
        $adminPass = $_POST['admin_pass'];
        if (strlen($adminPass) < 8) {
            throw new Exception("Admin password must be at least 8 characters long");
        }
        if (!preg_match('/^(?=.*[A-Z].*[A-Z])(?=.*[!@#$%^&*])(?=.*[0-9])(?=.*[a-z]).{8,}$/', $adminPass)) {
            throw new Exception("Admin password does not meet complexity requirements");
        }

        // Hash ONLY the admin password - store actual passwords for DB and RPC
        $hashedAdminPass = password_hash($adminPass, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost' => 4,
            'threads' => 1
        ]);

        // Store actual passwords for DB and RPC (not hashed)
        $dbPass = $_POST['db_pass'];
        $rpcPass = $_POST['rpc_pass'];

        // Escape special characters for INI file
        $escapedAdminPass = '"' . addslashes($hashedAdminPass) . '"';
        $escapedDbPass = '"' . addslashes($dbPass) . '"';
        $escapedRpcPass = '"' . addslashes($rpcPass) . '"';

        // Validate file path to prevent directory traversal
        $configPath = realpath(__DIR__) . DIRECTORY_SEPARATOR . 'importer.conf';
        if (dirname($configPath) !== realpath(__DIR__)) {
            throw new Exception("Invalid configuration file path");
        }

        // Set secure file permissions before writing
        if (file_exists($configPath)) {
            chmod($configPath, 0600);
        }

        $configContent = "; Database Configuration\n" .
            "DB_HOST=" . filter_var($_POST['db_host'], FILTER_SANITIZE_STRING) . "\n" .
            "DB_NAME=" . filter_var($_POST['db_name'], FILTER_SANITIZE_STRING) . "\n" .
            "DB_USER=" . filter_var($_POST['db_user'], FILTER_SANITIZE_STRING) . "\n" .
            "DB_PASS=" . $escapedDbPass . "\n\n" .
            "; RPC Configuration\n" .
            "RPC_HOST=" . filter_var($_POST['rpc_host'], FILTER_SANITIZE_STRING) . "\n" .
            "RPC_PORT=" . filter_var($_POST['rpc_port'], FILTER_VALIDATE_INT) . "\n" .
            "RPC_USER=" . filter_var($_POST['rpc_user'], FILTER_SANITIZE_STRING) . "\n" .
            "RPC_PASSWORD=" . $escapedRpcPass . "\n\n" .
            "; Admin Configuration\n" .
            "ADMIN_PASSWORD=" . $escapedAdminPass . "\n\n" .
            "; Import Settings\n" .
            "LOCK_FILE_PATH=import.lock\n" .
            "MAX_MEMORY=1G\n";

        // Write configuration with secure permissions
        if (file_put_contents($configPath, $configContent, LOCK_EX) === false) {
            throw new Exception("Failed to write configuration file");
        }
        chmod($configPath, 0600);

        // Verify the configuration file
        if (@parse_ini_file($configPath) === false) {
            @unlink($configPath);
            throw new Exception("Generated configuration file is invalid");
        }

        // Clear sensitive data from memory
        $adminPass = null;
        $dbPass = null;
        $rpcPass = null;
        $hashedAdminPass = null;
        $configContent = null;
        
        // Redirect with CSRF token
        $_SESSION['config_token'] = bin2hex(random_bytes(32));
        header("Location: " . $_SERVER['PHP_SELF'] . "?token=" . $_SESSION['config_token']);
        exit;
    } catch (Exception $e) {
        error_log("Configuration error: " . $e->getMessage());
        echo '<div class="alert alert-danger">Error: Configuration could not be saved</div>';
        exit;
    }
}

// === Initial Setup ===
// Configure error reporting and session handling
ini_set('display_errors', 1);
error_reporting(E_ALL);
ini_set('session.save_handler', 'files');
// ini_set('session.save_path', '/tmp');

// Detect AJAX requests for API endpoints
$isAjax = isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest';

// Initialize session for authentication
session_start();

if (isset($_GET['mark_instructions_seen']) && $isAjax) {
    $_SESSION['has_seen_instructions'] = true;
    echo json_encode(['success' => true]);
    exit;
}

if (isset($_GET['clear_session']) && $isAjax) {
    $_SESSION = array();
    if (isset($_COOKIE[session_name()])) {
        setcookie(session_name(), '', time()-3600, '/');
    }
    session_destroy();
    echo json_encode(['success' => true]);
    exit;
}

/**
 * Authentication Handler
 * Processes login attempts and manages session state
 */
if (isset($_POST['password'])) {
    // Get the stored hashed password from the config file
    $config = parse_ini_file(__DIR__ . '/importer.conf');
    $storedHash = trim($config['ADMIN_PASSWORD'], '"');
    
    if (password_verify($_POST['password'], $storedHash)) {
        $_SESSION['authenticated'] = true;
        error_log("Authentication successful, session set: " . print_r($_SESSION, true));
        if (!isset($_SESSION['has_seen_instructions'])) {
            $_SESSION['has_seen_instructions'] = false;
        }
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $login_error = 'Invalid password';
        error_log("Authentication failed");
    }
}

/**
 * Logout Handler
 * Clears session and redirects to login page
 */
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Check authentication for non-AJAX requests
if (!$isAjax && !isset($_SESSION['authenticated'])) {
    ?>
    <!DOCTYPE html>
    <html lang="en" data-bs-theme="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login - Blockchain Import Progress</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            :root {
                color-scheme: dark;
                --bs-body-color: #dee2e6;
                --bs-body-bg: #212529;
            }
            body {
                background-color: var(--bs-body-bg);
                color: var(--bs-body-color);
                height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .login-form {
                max-width: 400px;
                width: 90%;
                padding: 2rem;
                background: #2c3338;
                border-radius: 8px;
                box-shadow: 0 0 20px rgba(0,0,0,0.3);
            }
        </style>
    </head>
    <body>
        <div class="login-form">
            <h2 class="text-center mb-4">Blockchain Import</h2>
            <form method="POST" action="">
                <?php if (isset($login_error)): ?>
                    <div class="alert alert-danger"><?php echo htmlspecialchars($login_error); ?></div>
                <?php endif; ?>
                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    <input type="password" class="form-control bg-dark text-light" id="password" name="password" required autofocus>
                </div>
                <button type="submit" class="btn btn-primary w-100">Login</button>
            </form>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    <?php
    exit;
}

/**
 * Checks lock file permissions and status
 * Verifies both directory and lock file are writable
 * 
 * @return array ['success' => bool, 'error' => string|null]
 */
function checkLockFilePermissions() {
    $dir = __DIR__;
    if (!is_writable($dir)) {
        return ['success' => false, 'error' => 'Directory is not writable: ' . $dir];
    }
    
    if (file_exists(LOCK_FILE) && !is_writable(LOCK_FILE)) {
        return ['success' => false, 'error' => 'Lock file exists but is not writable'];
    }
    
    return ['success' => true];
}

/**
 * AJAX Request Handler
 * Processes all API endpoints for blockchain import operations
 */
if ($isAjax) {
    // Ensure clean output buffer
    while (ob_get_level()) ob_end_clean();
    
    // Set proper headers
    header('Content-Type: application/json');
    header('X-Content-Type-Options: nosniff');
    
    // Add these new endpoints in the AJAX handling section, before the existing endpoints
    if (isset($_GET['check_lock'])) {
        $locked = file_exists(LOCK_FILE);
        $pid = $locked ? @file_get_contents(LOCK_FILE) : null;
        
        if ($locked && $pid && function_exists('posix_kill')) {
            $locked = @posix_kill($pid, 0);
            if (!$locked) {
                @unlink(LOCK_FILE);
            }
        }
        
        echo json_encode([
            'locked' => $locked,
            'pid' => $pid
        ]);
        exit;
    }

    if (isset($_GET['acquire_lock'])) {
        $permCheck = checkLockFilePermissions();
        if (!$permCheck['success']) {
            echo json_encode(['success' => false, 'error' => $permCheck['error']]);
            exit;
        }

        if (file_exists(LOCK_FILE)) {
            $pid = @file_get_contents(LOCK_FILE);
            if ($pid && function_exists('posix_kill') && @posix_kill($pid, 0)) {
                echo json_encode(['success' => false, 'error' => 'Import already running']);
                exit;
            }
            @unlink(LOCK_FILE);
        }

        $currentPid = getmypid();
        if ($currentPid === false) {
            echo json_encode(['success' => false, 'error' => 'Failed to get process ID']);
            exit;
        }

        if (file_put_contents(LOCK_FILE, $currentPid) === false) {
            $error = error_get_last();
            echo json_encode(['success' => false, 'error' => 'Failed to create lock file: ' . ($error['message'] ?? 'Unknown error')]);
            exit;
        }

        echo json_encode(['success' => true]);
        exit;
    }

    if (isset($_GET['release_lock'])) {
        if (file_exists(LOCK_FILE)) {
            if (@unlink(LOCK_FILE)) {
                echo json_encode(['success' => true]);
            } else {
                echo json_encode(['success' => false, 'error' => 'Failed to delete lock file']);
            }
        } else {
            echo json_encode(['success' => true]);
        }
        exit;
    }

    if ($isAjax && isset($_GET['server_stats'])) {
        try {
            // Ensure clean output buffer
            while (ob_get_level()) ob_end_clean();
            
            $stats = [
                'load' => null,
                'iowait' => null,
                'error' => null
            ];
            
            // Get load average safely
            if (function_exists('sys_getloadavg')) {
                $load = @sys_getloadavg();
                if ($load !== false && isset($load[0])) {
                    $stats['load'] = (float)$load[0];
                }
            }
            
            // Get IO wait using iostat if available
            if (function_exists('shell_exec')) {
                try {
                    $raw_output = @shell_exec("iostat -c 1 2 2>/dev/null");
                    
                    if ($raw_output !== null) {
                        $lines = explode("\n", trim($raw_output));
                        
                        // Get the last valid line
                        $last_line = null;
                        foreach (array_reverse($lines) as $line) {
                            if (preg_match('/^\s*[\d.]+/', $line)) {
                                $last_line = $line;
                                break;
                            }
                        }
                        
                        if ($last_line) {
                            // Split and clean the line
                            $values = array_values(array_filter(preg_split('/\s+/', trim($last_line))));
                            
                            // iowait should be the 4th value (index 3)
                            if (isset($values[3]) && is_numeric($values[3])) {
                                $iowait = floatval($values[3]);
                                
                                // Only set if we got a valid value
                                if ($iowait !== false && $iowait >= 0) {
                                    $stats['iowait'] = $iowait;
                                }
                            }
                        }
                    }
                } catch (Exception $e) {
                    $stats['error'] = 'iostat error: ' . $e->getMessage();
                }
            }
            
            header('Content-Type: application/json');
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            echo json_encode($stats);
            exit;
        } catch (Exception $e) {
            header('Content-Type: application/json');
            echo json_encode([
                'load' => null,
                'iowait' => null,
                'error' => $e->getMessage()
            ]);
            exit;
        }
    }

    // Speed check endpoint
    if ($isAjax && isset($_GET['speed_check'])) {
        try {
            // Ensure clean output buffer
            while (ob_get_level()) {
                ob_end_clean();
            }

            // Set proper JSON headers
            header('Content-Type: application/json');
            header('X-Content-Type-Options: nosniff');

            require_once __DIR__ . '/BlockchainImporter.php';
            $importer = new BlockchainImporter();
            $status = $importer->getStatus();
            
            // Get the current timestamp and height
            $currentTime = time();
            $currentHeight = $status['last_imported_height'];
            
            // Initialize or get session data
            if (!isset($_SESSION['speed_stats'])) {
                $_SESSION['speed_stats'] = [
                    'last_check_time' => $currentTime,
                    'last_check_height' => $currentHeight,
                    'speed_history' => []
                ];
            }
            
            // Calculate speed only if we have previous data
            $timeDiff = $currentTime - $_SESSION['speed_stats']['last_check_time'];
            $heightDiff = $currentHeight - $_SESSION['speed_stats']['last_check_height'];
            
            // Update session with current values
            $_SESSION['speed_stats']['last_check_time'] = $currentTime;
            $_SESSION['speed_stats']['last_check_height'] = $currentHeight;
            
            // Limit size of speed history in session
            if (isset($_SESSION['speed_stats']['speed_history'])) {
                $_SESSION['speed_stats']['speed_history'] = array_slice(
                    $_SESSION['speed_stats']['speed_history'], 
                    -50  // Keep only last 50 entries
                );
            }
            
            // Create response data
            $response = [
                'success' => true,
                'current_height' => $currentHeight,
                'target_height' => $status['current_height'],
                'timestamp' => $currentTime
            ];

            // Encode with error checking
            $jsonResponse = json_encode($response, JSON_THROW_ON_ERROR);
            if ($jsonResponse === false) {
                throw new Exception('JSON encoding failed');
            }

            echo $jsonResponse;
            exit;

        } catch (Exception $e) {
            // Ensure clean output for errors
            while (ob_get_level()) {
                ob_end_clean();
            }

            http_response_code(500);
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage()
            ], JSON_THROW_ON_ERROR);
            exit;
        }
    }
}

/**
 * Main Import Process
 * Handles the actual blockchain import operation
 */
if (!$isAjax) {
    // Get initial status
    require_once __DIR__ . '/BlockchainImporter.php';
    $importer = new BlockchainImporter();
    $initialStatus = $importer->getStatus();
    ?>
    <!DOCTYPE html>
    <html lang="en" data-bs-theme="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Blockchain Import Progress</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            :root {
                color-scheme: dark;
                --bs-body-color: #dee2e6;
                --bs-body-bg: #212529;
            }
            
            body {
                background-color: var(--bs-body-bg);
                color: var(--bs-body-color);
            }
            
            #output-box {
                height: 200px;
                overflow-y: auto;
                background: #1a1a1a;
                color: #00ff00;
                font-family: monospace;
                padding: 10px;
                margin: 20px 0;
                border: 1px solid #444;
            }
            
            .progress {
                height: 25px;
                background-color: #2c3338;
            }
            
            .card {
                background-color: #2c3338;
                border-color: #444;
            }
            
            .text-muted {
                color: #8f959b !important;
            }
            
            .btn-group .btn {
                border-color: #444;
            }
            #sync-speed, #sync-eta {
                transition: color 0.3s ease;
            }
            
            #sync-speed.text-success {
                color: #28a745 !important;
            }
            
            .card h2 {
                font-variant-numeric: tabular-nums;
                font-feature-settings: "tnum";
            }
            .calculating {
                display: inline-flex;
                align-items: center;
            }

            .calculating::after {
                content: '...';
                width: 1.5em;
                animation: dots 1.5s steps(4, end) infinite;
            }

            @keyframes dots {
                0%, 20% { content: ''; }
                40% { content: '.'; }
                60% { content: '..'; }
                80%, 100% { content: '...'; }
            }
        </style>
    </head>
    <body>
    <div class="modal fade" id="instructionsModal" tabindex="-1" data-bs-backdrop="static" aria-labelledby="instructionsModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg">
        <div class="modal-content bg-dark text-light">
            <div class="modal-header border-secondary">
                <h5 class="modal-title">Getting Started</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" data-bs-target="#instructionsModal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <!-- Navigation tabs -->
                <ul class="nav nav-tabs mb-3" id="instructionTabs" role="tablist">
                    <li class="nav-item" role="presentation">
                        <button class="nav-link active" id="quickstart-tab" data-bs-toggle="tab" 
                                data-bs-target="#quickstart" type="button" role="tab">Quick Start</button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="features-tab" data-bs-toggle="tab" 
                                data-bs-target="#features" type="button" role="tab">Features</button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="settings-tab" data-bs-toggle="tab" 
                                data-bs-target="#settings-guide" type="button" role="tab">Settings</button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="troubleshooting-tab" data-bs-toggle="tab" 
                                data-bs-target="#troubleshooting" type="button" role="tab">Troubleshooting</button>
                    </li>
                </ul>

                <!-- Tab content -->
                <div class="tab-content" id="instructionTabContent">
                    <!-- Quick Start Tab -->
                    <div class="tab-pane fade show active" id="quickstart" role="tabpanel">
                        <h6 class="mb-3">Quick Start Guide</h6>
                        <ol class="mb-4">
                            <li>Click "Start Import" to begin the blockchain synchronization</li>
                            <li>Monitor progress in real-time with the status indicators</li>
                            <li>Use the Settings panel to customize import behavior</li>
                            <li>The import can be safely stopped and resumed later</li>
                        </ol>
                    </div>

                    <!-- Features Tab -->
                    <div class="tab-pane fade" id="features" role="tabpanel">
                        <h6 class="mb-3">Key Features</h6>
                        <ul class="mb-4">
                            <li><strong>Real-time Monitoring:</strong> Watch the import progress as it happens. (Updates every Batch)</li>
                            <li><strong>Auto-Continue:</strong> Automatically process new blocks as they arrive</li>
                            <li><strong>Performance Metrics:</strong> Monitor speed, ETA, and system load</li>
                            <li><strong>Customizable Settings:</strong> Adjust batch size and processing delay</li>
                            <li><strong>Safe Operations:</strong> Built-in safeguards prevent data corruption</li>
                        </ul>
                    </div>

                    <!-- Settings Guide Tab -->
                    <div class="tab-pane fade" id="settings-guide" role="tabpanel">
                        <h6 class="mb-3">Settings Guide</h6>
                        <div class="mb-4">
                            <h7 class="fw-bold">Batch Size Control</h7>
                            <p>Adjust how many blocks are processed in each batch:</p>
                            <ul>
                                <li>Higher values (>1000): Faster import but more memory usage</li>
                                <li>Lower values (<1000): Slower import but less resource intensive</li>
                                <li>Recommended: Start with 1000 and adjust based on system performance</li>
                            </ul>
                        </div>
                        <div class="mb-4">
                            <h7 class="fw-bold">Processing Delay</h7>
                            <p>Control the delay between operations:</p>
                            <ul>
                                <li>Higher values: Reduced system load, slower import</li>
                                <li>Lower values: Faster import, higher system load</li>
                                <li>Recommended: 10ms for balanced performance</li>
                            </ul>
                        </div>
                    </div>

                    <!-- Troubleshooting Tab -->
                    <div class="tab-pane fade" id="troubleshooting" role="tabpanel">
                        <h6 class="mb-3">Common Issues</h6>
                        <div class="accordion" id="troubleshootingAccordion">
                            <div class="accordion-item bg-dark">
                                <h2 class="accordion-header">
                                    <button class="accordion-button collapsed bg-dark text-light" type="button" data-bs-toggle="collapse" data-bs-target="#issue1">
                                        Import Seems Stuck
                                    </button>
                                </h2>
                                <div id="issue1" class="accordion-collapse collapse" data-bs-parent="#troubleshootingAccordion">
                                    <div class="accordion-body">
                                        Try reducing the batch size and increasing the processing delay. If issues persist, stop and restart the import.
                                    </div>
                                </div>
                            </div>
                            <div class="accordion-item bg-dark">
                                <h2 class="accordion-header">
                                    <button class="accordion-button collapsed bg-dark text-light" type="button" data-bs-toggle="collapse" data-bs-target="#issue2">
                                        High System Load
                                    </button>
                                </h2>
                                <div id="issue2" class="accordion-collapse collapse" data-bs-parent="#troubleshootingAccordion">
                                    <div class="accordion-body">
                                        Increase the processing delay and reduce batch size to lower system resource usage.
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="form-check mt-4">
                    <input type="checkbox" class="form-check-input" id="dontShowAgainInstructions">
                    <label class="form-check-label" for="dontShowAgainInstructions">Don't show this again</label>
                </div>
            </div>
            <div class="modal-footer border-secondary">
                <button type="button" class="btn btn-primary" data-bs-dismiss="modal" data-bs-target="#instructionsModal">Got it!</button>
            </div>
        </div>
    </div>
</div>
        <div class="container mt-4">
            <div class="row mb-3">
                <div class="col-12 d-flex justify-content-between align-items-center">
                    <div>
                        <div class="btn-group" role="group">
                            <button id="startBtn" class="btn btn-success">Start Import</button>
                            <button id="stopBtn" class="btn btn-danger" disabled>Stop Import</button>
                            <button id="settingsBtn" class="btn btn-info" data-bs-toggle="modal" data-bs-target="#settingsModal">
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-gear-fill" viewBox="0 0 16 16">
                                    <path d="M9.405 1.05c-.413-1.4-2.397-1.4-2.81 0l-.1.34a1.464 1.464 0 0 1-2.105.872l-.31-.17c-1.283-.698-2.686.705-1.987 1.987l.169.311c.446.82.023 1.841-.872 2.105l-.34.1c-1.4.413-1.4 2.397 0 2.81l.34.1a1.464 1.464 0 0 1 .872 2.105l-.17.31c-.698 1.283.705 2.686 1.987 1.987l.311-.169a1.464 1.464 0 0 1 2.105.872l.1.34c.413 1.4 2.397 1.4 2.81 0l.1-.34a1.464 1.464 0 0 1 2.105-.872l.31.17c1.283.698 2.686-.705 1.987-1.987l-.169-.311a1.464 1.464 0 0 1 .872-2.105l.34-.1c1.4-.413 1.4-2.397 0-2.81l-.34-.1a1.464 1.464 0 0 1-.872-2.105l.17-.31c.698-1.283-.705-2.686-1.987-1.987l-.311.169a1.464 1.464 0 0 1-2.105-.872l-.1-.34zM8 10.93a2.929 2.929 0 1 1 0-5.86 2.929 2.929 0 0 1 0 5.858z"/>
                                </svg>
                            </button>
                        </div>
                        <div class="form-check form-switch d-inline-block ms-3">
                            <input class="form-check-input" type="checkbox" id="autoContinue">
                            <label class="form-check-label" for="autoContinue">Auto Continue</label>
                        </div>
                        <div class="server-stats d-inline-block ms-3">
                            <small class="text-muted">
                                Load: <span id="server-load">-</span>
                                <span class="ms-2">IO Wait: <span id="io-wait">-</span>%</span>
                            </small>
                        </div>
                    </div>
                    <div>
                        <a href="?logout=1" class="btn btn-outline-danger">Logout</a>
                    </div>
                </div>
            </div>

            <div class="row mb-3">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-body">
                        <h5 class="card-title">Batch Size Control</h5>
                            <label for="speedControl" class="form-label"><span id="speedValue">1000</span> Blocks/Batch</label>
                            <input type="range" class="form-range" id="speedControl" min="100" max="10000" step="100" value="1000">
                            <small class="text-muted">Higher values increase memory usage but improve import speed.</small>
                            
                            <!-- New RPC Batch Size Slider -->
                            <div class="mt-3">
                                <label for="rpcBatchSizeInput" class="form-label">RPC Batch Size: <span id="rpcBatchValue">500</span> blocks</label>
                                <input type="range" class="form-range" 
                                       id="rpcBatchSizeInput" 
                                       min="100" max="4000" step="100" value="500">
                                <small class="text-muted">Number of blocks to fetch per RPC call. Lower values reduce memory usage.</small>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-body">
                            <h5 class="card-title">System Load Control</h5>
                            <label for="delayControl" class="form-label">Processing Delay: <span id="delayValue">10</span> ms</label>
                            <input type="range" class="form-range" id="delayControl" min="0" max="200" step="1" value="10">
                            <small class="text-muted">Higher values reduce CPU/IO load by adding delays between operations!<BR> </small>
                        </div>
                    </div>
                </div>
            </div>

            <h5 class="card-title mb-2">Sync Progress!</h5>
            <div class="progress mb-3">
                <div id="progress-bar" class="progress-bar progress-bar-striped progress-bar-animated" 
                     role="progressbar" style="width: <?php echo $initialStatus['import_progress']; ?>%">
                     <?php echo number_format($initialStatus['import_progress'], 2); ?>%
                </div>
            </div>

            <div class="card mb-3">
                <div class="card-body">
                    <div class="row">
                        <div class="col-6">
                            <h5 class="card-title">Sync Speed</h5>
                            <h2 id="sync-speed">0</h2>
                            <small class="text-muted">blocks/minute</small>
                        </div>
                        <div class="col-6">
                            <h5 class="card-title">ETA - large chains will slow down as height increases!</h5>
                            <h2 id="sync-eta">-</h2>
                            <small class="text-muted">to completion</small>
                        </div>
                    </div>
                </div>
            </div>

            <div class="mb-3">
                <span>DB Height: <span id="db-height"><?php echo number_format($initialStatus['last_imported_height']); ?></span></span>
                <span class="mx-2">/</span>
                <span>RPC Height: <span id="rpc-height"><?php echo number_format($initialStatus['current_height']); ?></span></span>
            </div>

            <div id="output-box" class="border"></div>
        </div>
        <!-- Settings Modal -->
        <div class="modal fade" id="settingsModal" tabindex="-1" role="dialog" data-bs-backdrop="static">
            <div class="modal-dialog" role="document">
                <div class="modal-content bg-dark">
                    <div class="modal-header border-secondary">
                        <h5 class="modal-title" id="settingsModalLabel">Client Settings</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="progressIntervalInput" class="form-label">Progress Update Interval (ms)</label>
                            <input type="number" class="form-control bg-dark text-light" 
                                   id="progressIntervalInput" 
                                   value="2000" min="1000" max="10000">
                            <small class="text-muted">How often to check import progress (1000-10000ms)</small>
                        </div>
                        <div class="mb-3">
                            <label for="speedAverageWindowInput" class="form-label">Speed Average Window (samples)</label>
                            <input type="number" class="form-control bg-dark text-light" 
                                   id="speedAverageWindowInput" 
                                   value="5" min="1" max="20">
                            <small class="text-muted">Number of samples to average for speed calculation (1-20)</small>
                        </div>
                        <div class="mb-3">
                            <label for="speedIntervalInput" class="form-label">Speed Update Interval (ms)</label>
                            <input type="number" class="form-control bg-dark text-light" 
                                   id="speedIntervalInput" 
                                   value="5000" min="1000" max="10000">
                            <small class="text-muted">How often to update speed metrics (1000-10000ms)</small>
                        </div>
                        <div class="mb-3">
                            <label for="maxOutputLinesInput" class="form-label">Output Box Max Lines</label>
                            <input type="number" class="form-control bg-dark text-light" 
                                   id="maxOutputLinesInput" 
                                   value="100" min="10" max="1000">
                            <small class="text-muted">Maximum number of lines to keep in output box (10-1000)</small>
                        </div>
                        <div class="mb-3 form-check">
                            <input type="checkbox" class="form-check-input" id="enableSoundAlertsInput" checked>
                            <label class="form-check-label" for="enableSoundAlertsInput">Enable Sound Alerts</label>
                        </div>
                        <div class="mb-3">
                            <label for="soundVolumeInput" class="form-label">Sound Volume: <span id="volumeValue">30</span>%</label>
                            <input type="range" class="form-range" 
                                   id="soundVolumeInput" 
                                   min="0" max="100" value="30">
                        </div>
                        <div class="mb-3">
                            <label for="enableAutoRetryInput" class="form-label">Auto-Retry on Error</label>
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" 
                                       id="enableAutoRetryInput" checked>
                                <label class="form-check-label" for="enableAutoRetryInput">Enable automatic retry on errors</label>
                            </div>
                        </div>
                        <div class="mb-3">
                            <label for="maxRetryAttemptsInput" class="form-label">Max Retry Attempts</label>
                            <input type="number" class="form-control bg-dark text-light" 
                                   id="maxRetryAttemptsInput" 
                                   value="3" min="1" max="10">
                            <small class="text-muted">Maximum number of retry attempts (1-10)</small>
                        </div>
                        <div class="mb-3">
                            <label for="retryDelayInput" class="form-label">Retry Delay (ms)</label>
                            <input type="number" class="form-control bg-dark text-light" 
                                   id="retryDelayInput" 
                                   value="1000" min="500" max="5000" step="500">
                            <small class="text-muted">Delay between retry attempts (500-5000ms)</small>
                        </div>
                        <div class="mb-3 form-check">
                            <input type="checkbox" class="form-check-input" id="enableConsoleOutput" checked>
                            <label class="form-check-label" for="enableConsoleOutput">Enable Console Logging</label>
                            <small class="text-muted d-block">Output detailed information to browser console</small>
                        </div>
                        <div class="mb-3">
                            <label for="rpcBatchSizeInput" class="form-label">RPC Batch Size</label>
                            <input type="number" class="form-control bg-dark text-light" 
                                   id="rpcBatchSizeInput" 
                                   value="25" min="1" max="2000">
                            <small class="text-muted">Number of blocks to fetch in a single RPC batch (1-2000)</small>
                        </div>
                        <div class="mb-3">
                            <button type="button" class="btn btn-secondary" onclick="testSounds()">Test Sounds</button>
                        </div>
                        <!-- Add a divider before reset options -->
                        <hr class="border-secondary my-4">
                        
                        <!-- Reset Options Section -->
                        <div class="mb-3">
                            <h6 class="mb-3">Reset Options</h6>
                            <button type="button" class="btn btn-danger" id="clearSessionBtn">
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-trash3 me-2" viewBox="0 0 16 16">
                                    <path d="M6.5 1h3a.5.5 0 0 1 .5.5v1H6v-1a.5.5 0 0 1 .5-.5M11 2.5v-1A1.5 1.5 0 0 0 9.5 0h-3A1.5 1.5 0 0 0 5 1.5v1H2.506a.58.58 0 0 0-.01 0H1.5a.5.5 0 0 0 0 1h.538l.853 10.66A2 2 0 0 0 4.885 16h6.23a2 2 0 0 0 1.994-1.84l.853-10.66h.538a.5.5 0 0 0 0-1h-.995a.59.59 0 0 0-.01 0zm1.958 1-.846 10.58a1 1 0 0 1-.997.92h-6.23a1 1 0 0 1-.997-.92L3.042 3.5zm-7.487 1a.5.5 0 0 1 .528.47l.5 8.5a.5.5 0 0 1-.998.06L5 5.03a.5.5 0 0 1 .47-.53Zm5.058 0a.5.5 0 0 1 .47.53l-.5 8.5a.5.5 0 1 1-.998-.06l.5-8.5a.5.5 0 0 1 .528-.47ZM8 4.5a.5.5 0 0 1 .5.5v8.5a.5.5 0 0 1-1 0V5a.5.5 0 0 1 .5-.5"/>
                                </svg>
                                Clear Session Data
                            </button>
                            <small class="text-muted d-block mt-2">This will clear all settings and preferences, and log you out</small>
                        </div>
                        <!-- Add this just before the settings modal footer -->
                        <hr class="border-secondary my-4">
                        <div class="mb-3">
                            <h6 class="mb-3">Master Reset</h6>
                            <a href="master_reset.php" class="btn btn-danger" id="masterResetBtn" onclick="window.location.href='master_reset.php'; return false;">
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-exclamation-triangle-fill me-2" viewBox="0 0 16 16">
                                    <path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5zm.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2z"/>
                                </svg>
                                Master Reset
                            </a>
                            <small class="text-danger d-block mt-2">Warning: This will delete all data, drop all tables, and clear all settings. This action cannot be undone.</small>
                        </div>
                    </div>
                    <div class="modal-footer border-secondary">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-primary" id="saveSettings">Save Changes</button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Instructions Modal -->
        <div class="modal fade" id="instructionsModal" tabindex="-1" aria-labelledby="instructionsModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-lg">
                <div class="modal-content bg-dark text-light">
                    <div class="modal-header border-secondary">
                        <h5 class="modal-title" id="instructionsModalLabel">Welcome to Blockchain Importer</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <h6 class="mb-3">Getting Started</h6>
                        <ol class="mb-4">
                            <li>Click "Start Import" to begin importing blockchain data</li>
                            <li>Monitor progress in real-time with the progress bar and stats</li>
                            <li>Use "Auto Continue" to automatically process new blocks</li>
                        </ol>

                        <h6 class="mb-3">Key Features</h6>
                        <ul class="mb-4">
                            <li>Real-time progress monitoring</li>
                            <li>Automatic speed calculation</li>
                            <li>ETA to completion</li>
                            <li>Server load monitoring</li>
                            <li>Sound alerts for important events</li>
                        </ul>

                        <h6 class="mb-3">Tips</h6>
                        <ul>
                            <li>Adjust batch size in settings for optimal performance</li>
                            <li>Enable sound alerts to get notified of completion or errors</li>
                            <li>Check server stats to monitor system load</li>
                        </ul>
                    </div>
                    <div class="modal-footer border-secondary">
                        <div class="form-check me-auto">
                            <input type="checkbox" class="form-check-input" id="dontShowAgain">
                            <label class="form-check-label" for="dontShowAgain">Don't show again</label>
                        </div>
                        <button type="button" class="btn btn-primary" data-bs-dismiss="modal">Got it!</button>
                    </div>
                </div>
            </div>
        </div>

        <script>
        const viewedTabs = {
            'quickstart': true,  // Set to true by default since it's the first visible tab
            'features': false,
            'settings-guide': false,
            'troubleshooting': false
        };

        document.addEventListener('DOMContentLoaded', function() {
            const instructionsModal = document.getElementById('instructionsModal');
            const closeButton = instructionsModal.querySelector('.btn-close');
            const gotItButton = instructionsModal.querySelector('.btn-primary');
            
            // Disable close buttons initially
            closeButton.disabled = true;
            gotItButton.disabled = true;
            
            // Add tab change listener
            document.querySelectorAll('button[data-bs-toggle="tab"]').forEach(tab => {
                tab.addEventListener('shown.bs.tab', function(event) {
                    const targetId = event.target.getAttribute('data-bs-target').replace('#', '');
                    viewedTabs[targetId] = true;
                    
                    // Check if all tabs have been viewed
                    const allTabsViewed = Object.values(viewedTabs).every(viewed => viewed);
                    
                    if (allTabsViewed) {
                        closeButton.disabled = false;
                        gotItButton.disabled = false;
                        gotItButton.innerHTML = 'Got it! <small>(All pages viewed)</small>';
                    }
                });
            });
            
            // Prevent modal from being closed with escape key or clicking outside
            const modalInstance = new bootstrap.Modal(instructionsModal, {
                backdrop: 'static',
                keyboard: false
            });
            
            // Update the Got It button text initially
            gotItButton.innerHTML = 'Got it! <small>(View remaining pages)</small>';
        });

        let outputBox = document.getElementById('output-box');
        let progressBar = document.getElementById('progress-bar');
        let dbHeightSpan = document.getElementById('db-height');
        let rpcHeightSpan = document.getElementById('rpc-height');
        let lastHeight = <?php echo $initialStatus['last_imported_height']; ?>;
        let isRunning = false;
        let timeoutId = null;
        let syncSpeedElement = document.getElementById('sync-speed');
        let syncEtaElement = document.getElementById('sync-eta');
        let speedUpdateInterval = null;
        let uiUpdateInterval = null;
        let speedHistory = [];
        let hasSeenValidSpeed = false; // Add this with other state variables at the top
        let cleanupInterval = null;
        const settings = {
            progressInterval: 2000,
            speedInterval: 5000,
            maxOutputLines: 100,
            enableSoundAlerts: true,
            soundVolume: 0.3, // Add this new setting
            speedAverageWindow: 5,
            enableAutoRetry: true,
            maxRetryAttempts: 3,
            retryDelay: 1000,
            enableConsoleOutput: true,
            rpcBatchSize: 25,
            cleanupInterval: 300000  // 5 minutes in milliseconds
        };
        let isLocked = false;
        let isStoppingRequested = false;

        function debugLog(...args) {
            if (settings.enableConsoleOutput) {
                console.log(...args);
            }
        }

        // Initialize UI elements safely
        function initializeUI() {
            debugLog('Initializing UI...');
            
            // Initialize critical elements with error checking
            const criticalElements = {
                outputBox: 'output-box',
                progressBar: 'progress-bar',
                dbHeightSpan: 'db-height',
                rpcHeightSpan: 'rpc-height',
                syncSpeedElement: 'sync-speed',
                syncEtaElement: 'sync-eta',
                startBtn: 'startBtn',
                stopBtn: 'stopBtn',
                autoContinueCheckbox: 'autoContinue',
                speedControl: 'speedControl',
                speedValue: 'speedValue',
                delayControl: 'delayControl',
                delayValue: 'delayValue'
            };

            // Initialize all elements and store them in window object
            for (const [varName, id] of Object.entries(criticalElements)) {
                const element = document.getElementById(id);
                if (!element) {
                    console.warn(`Critical element not found: ${id}`);
                    continue;
                }
                window[varName] = element;
            }

            // Optional elements - handle separately
            const volumeSlider = document.getElementById('soundVolume');
            const volumeDisplay = document.getElementById('volumeValue');
            if (volumeSlider && volumeDisplay) {
                volumeDisplay.textContent = volumeSlider.value;
            }
        }

        document.addEventListener('DOMContentLoaded', function() {
            initializeUI();
            loadSettings();
        });
        document.addEventListener('DOMContentLoaded', function() {
    const hasSeenInstructions = <?php echo isset($_SESSION['has_seen_instructions']) && $_SESSION['has_seen_instructions'] ? 'true' : 'false'; ?>;
    
    if (!hasSeenInstructions) {
        const instructionsModal = new bootstrap.Modal(document.getElementById('instructionsModal'));
        instructionsModal.show();
    }
    
    document.getElementById('instructionsModal').addEventListener('hidden.bs.modal', function () {
        const dontShowAgainInstructions = document.getElementById('dontShowAgainInstructions').checked;
        if (dontShowAgainInstructions) {
            fetch('import_blockchain_web.php?mark_instructions_seen=1', {
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });
        }
    });

    // Clear Session Data handling
    document.getElementById('clearSessionBtn').addEventListener('click', async function() {
        if (!confirm('Are you sure you want to clear all session data? This will log you out?')) {
            return;
        }

        try {
            const response = await fetch('import_blockchain_web.php?clear_session=1', {
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });

            if (!response.ok) {
                throw new Error('Network response was not ok');
            }

            const result = await response.json();
            
            if (result.success) {
                // Clear local storage
                localStorage.removeItem('importerSettings');
                
                // Redirect to login page
                window.location.href = 'import_blockchain_web.php?logout=1';
            } else {
                throw new Error(result.error || 'Failed to clear session');
            }
        } catch (error) {
            console.error('Error clearing session:', error);
            alert('Failed to clear session data. Please try again.');
        }
    });
});
        const sounds = {
            error: new Audio('data:audio/mpeg;base64,//uQxAAAAAAAAAAAAAAAAAAAAAAASW5mbwAAAA8AAAADAAAGhgBVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVWqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqr///////////////////////////////////////////8AAAA8TEFNRTMuOTlyAc0AAAAAAAAAABSAJAOkQgAAgAAABobXqlfbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//sQxAADwAABpAAAACAAADSAAAAETEFNRTMuOTkuNVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVQ=='),
            success: new Audio('data:audio/mpeg;base64,//uQxAAAAAAAAAAAAAAAAAAAAAAASW5mbwAAAA8AAAADAAAGhgBVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVWqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqr///////////////////////////////////////////8AAAA8TEFNRTMuOTlyAc0AAAAAAAAAABSAJAOkQgAAgAAABobXYt7YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//sQxAADwAABpAAAACAAADSAAAAETEFNRTMuOTkuNVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVQ==')
        };

        let lastSpeedCheck = {
            time: Date.now(),
            height: 0,
            lastBlockTime: Date.now()
        };
        function playSound(type) {
            if (!settings.enableSoundAlerts) return;
            
            debugLog(`Attempting to play sound: ${type}`);
            
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();
            
            if (type === 'success') {
                // Success sound: Pleasant "ding" with smooth fade
                oscillator.type = 'sine';
                oscillator.frequency.setValueAtTime(1318.51, audioContext.currentTime); // E6
                oscillator.frequency.setValueAtTime(1567.98, audioContext.currentTime + 0.03); // G6
                
                gainNode.gain.setValueAtTime(0, audioContext.currentTime);
                gainNode.gain.linearRampToValueAtTime(0.3 * settings.soundVolume, audioContext.currentTime + 0.01);
                gainNode.gain.exponentialRampToValueAtTime(0.01 * settings.soundVolume, audioContext.currentTime + 0.3);
                
                oscillator.connect(gainNode);
                gainNode.connect(audioContext.destination);
                
                oscillator.start();
                oscillator.stop(audioContext.currentTime + 0.3);
            } else {
                // Error sound: Gentle "double-beep" alert
                oscillator.type = 'sine';
                oscillator.frequency.setValueAtTime(466.16, audioContext.currentTime); // A#4/Bb4
                oscillator.frequency.setValueAtTime(369.99, audioContext.currentTime + 0.1); // F#4/Gb4
                
                gainNode.gain.setValueAtTime(0, audioContext.currentTime);
                gainNode.gain.linearRampToValueAtTime(0.2 * settings.soundVolume, audioContext.currentTime + 0.02);
                gainNode.gain.linearRampToValueAtTime(0.1 * settings.soundVolume, audioContext.currentTime + 0.08);
                gainNode.gain.linearRampToValueAtTime(0.2 * settings.soundVolume, audioContext.currentTime + 0.12);
                gainNode.gain.linearRampToValueAtTime(0, audioContext.currentTime + 0.3);
                
                oscillator.connect(gainNode);
                gainNode.connect(audioContext.destination);
                
                oscillator.start();
                oscillator.stop(audioContext.currentTime + 0.3);
            }

            // Clean up
            setTimeout(() => {
                audioContext.close();
            }, 1000);
        }
        function calculateAverageSpeed() {
            if (speedHistory.length < 2) {
                debugLog('Not enough samples for speed calculation');
                return 0;
            }
            
            // Get the oldest and newest measurements
            const oldest = speedHistory[0];
            const newest = speedHistory[speedHistory.length - 1];
            
            // Calculate total blocks and time difference
            const blockDiff = newest.height - oldest.height;
            const timeDiff = (newest.time - oldest.time) / 60000; // Convert to minutes
            
            const speed = timeDiff > 0 ? blockDiff / timeDiff : 0;
            
            debugLog('Speed calculation:', {
                samples: speedHistory.length,
                oldestHeight: oldest.height,
                newestHeight: newest.height,
                blockDiff,
                timeDiffMinutes: timeDiff,
                speed: speed
            });
            
            return speed;
        }

        function testSounds() {
            debugLog('Testing sounds...');
            playSound('success');
            setTimeout(() => playSound('error'), 1000);
        }
        function addSpeedToHistory(height, time) {
            // Add new measurement with validation
            if (typeof height === 'number' && typeof time === 'number') {
                speedHistory.push({ height, time });
                
                // Keep only the most recent measurements based on settings
                if (speedHistory.length > settings.speedAverageWindow) {
                    speedHistory = speedHistory.slice(-settings.speedAverageWindow);
                }
            }
            
            // Clear invalid entries
            speedHistory = speedHistory.filter(entry => 
                entry && 
                typeof entry.height === 'number' && 
                typeof entry.time === 'number' &&
                !isNaN(entry.height) && 
                !isNaN(entry.time)
            );
        }

        // Add this cleanup function
        function cleanupSpeedHistory() {
            const now = Date.now();
            const oneHourAgo = now - (60 * 60 * 1000);
            
            // Remove entries older than 1 hour
            speedHistory = speedHistory.filter(entry => entry.time > oneHourAgo);
        }

        // Call cleanup periodically
        setInterval(cleanupSpeedHistory, 5 * 60 * 1000); // Every 5 minutes

        let speedControl = document.getElementById('speedControl');
        let speedValue = document.getElementById('speedValue');
        let delayControl = document.getElementById('delayControl');
        let delayValue = document.getElementById('delayValue');

        // Load settings from localStorage
        function loadSettings() {
            const savedSettings = localStorage.getItem('importerSettings');
            if (savedSettings) {
                Object.assign(settings, JSON.parse(savedSettings));
                
                // Update form values with new IDs
                document.getElementById('progressIntervalInput').value = settings.progressInterval;
                document.getElementById('speedIntervalInput').value = settings.speedInterval;
                document.getElementById('maxOutputLinesInput').value = settings.maxOutputLines;
                document.getElementById('enableSoundAlertsInput').checked = settings.enableSoundAlerts;
                document.getElementById('soundVolumeInput').value = settings.soundVolume * 100;
                document.getElementById('volumeValue').textContent = Math.round(settings.soundVolume * 100);
                document.getElementById('speedAverageWindowInput').value = settings.speedAverageWindow;
                document.getElementById('enableAutoRetryInput').checked = settings.enableAutoRetry;
                document.getElementById('maxRetryAttemptsInput').value = settings.maxRetryAttempts;
                document.getElementById('retryDelayInput').value = settings.retryDelay;
                document.getElementById('enableConsoleOutput').checked = settings.enableConsoleOutput;
                document.getElementById('rpcBatchSizeInput').value = settings.rpcBatchSize;
            }
        }

        // Save settings to localStorage
        document.getElementById('saveSettings').addEventListener('click', function() {
            // Get the settings button that opens the modal
            const settingsButton = document.querySelector('[data-bs-target="#settingsModal"]');
            
            // Save settings
            settings.progressInterval = parseInt(document.getElementById('progressIntervalInput').value);
            settings.speedInterval = parseInt(document.getElementById('speedIntervalInput').value);
            settings.maxOutputLines = parseInt(document.getElementById('maxOutputLinesInput').value);
            settings.enableSoundAlerts = document.getElementById('enableSoundAlertsInput').checked;
            settings.soundVolume = parseInt(document.getElementById('soundVolumeInput').value) / 100;
            settings.speedAverageWindow = parseInt(document.getElementById('speedAverageWindowInput').value);
            settings.enableAutoRetry = document.getElementById('enableAutoRetryInput').checked;
            settings.maxRetryAttempts = parseInt(document.getElementById('maxRetryAttemptsInput').value);
            settings.retryDelay = parseInt(document.getElementById('retryDelayInput').value);
            settings.enableConsoleOutput = document.getElementById('enableConsoleOutput').checked;
            settings.rpcBatchSize = parseInt(document.getElementById('rpcBatchSizeInput').value);
            
            localStorage.setItem('importerSettings', JSON.stringify(settings));
            
            // Close modal and move focus back to the settings button
            const modal = bootstrap.Modal.getInstance(document.getElementById('settingsModal'));
            modal.hide();
            
            // Return focus to the button that opened the modal
            if (settingsButton) {
                setTimeout(() => {
                    settingsButton.focus();
                }, 100);
            }
            
            applySettings();
        });

        // Add event listener for modal hidden event
        document.getElementById('settingsModal').addEventListener('hidden.bs.modal', function () {
            // Remove focus from any elements inside the modal
            document.activeElement?.blur();
        });

        // Apply settings to active functionality
        function applySettings() {
            // Trim output box if needed
            const lines = outputBox.innerHTML.split('<br>');
            if (lines.length > settings.maxOutputLines) {
                outputBox.innerHTML = lines.slice(-settings.maxOutputLines).join('<br>');
            }

            // Adjust speed history array size if needed
            while (speedHistory.length > settings.speedAverageWindow) {
                speedHistory.shift();
            }
        }

        // Update speed value display
        speedControl.addEventListener('input', function() {
            speedValue.textContent = this.value;
        });

        // Update delay value display
        delayControl.addEventListener('input', function() {
            delayValue.textContent = this.value;
        });

        const startBtn = document.getElementById('startBtn');
        const stopBtn = document.getElementById('stopBtn');
        const autoContinueCheckbox = document.getElementById('autoContinue');

        async function handleFetchError(response) {
            if (response.status === 401) {
                playSound('error');
                window.location.reload();
                throw new Error('Authentication required');
            }
            if (!response.ok) {
                playSound('error');
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response;
        }

        async function checkLock() {
            try {
                const response = await fetch('import_blockchain_web.php?check_lock=1', {
                    headers: { 'X-Requested-With': 'XMLHttpRequest' }
                });
                
                await handleFetchError(response);
                const data = await response.json();
                return data.locked;
            } catch (error) {
                console.error('Lock check failed:', error);
                playSound('error');
                appendOutput('Lock check failed: ' + error.message);
                return false;
            }
        }

        function appendOutput(text) {
            const timestamp = new Date().toLocaleTimeString();
            outputBox.innerHTML += `[${timestamp}] ${text}<br>`;
            
            // Trim old lines if needed
            const lines = outputBox.innerHTML.split('<br>');
            if (lines.length > settings.maxOutputLines) {
                outputBox.innerHTML = lines.slice(-settings.maxOutputLines).join('<br>');
            }
            
            outputBox.scrollTop = outputBox.scrollHeight;
        }

        async function updateProgress() {
            if (!isRunning || isStoppingRequested) {
                await stopImport();
                return;
            }

            try {
                const baseUrl = new URL(window.location.href);
                const params = new URLSearchParams(baseUrl.search);
                
                // Set parameters...
                params.set('batch_size', speedControl.value);
                params.set('block_delay', delayControl.value);
                params.set('rpc_batch_size', settings.rpcBatchSize);
                if (params.get('token')) {
                    params.set('token', params.get('token'));
                }

                const fetchUrl = `${baseUrl.pathname}?${params.toString()}`;
                const response = await fetch(fetchUrl, {
                    headers: { 'X-Requested-With': 'XMLHttpRequest' }
                });

                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }

                const data = await response.json();

                // Check again if we should stop
                if (!isRunning || isStoppingRequested) {
                    await stopImport();
                    return;
                }

                if (data.error) {
                    throw new Error(data.error);
                }

                const dbHeight = parseInt(data.after.height);
                const rpcHeight = parseInt(data.blockchain_height);

                // Update UI elements...
                dbHeightSpan.textContent = dbHeight.toLocaleString();
                rpcHeightSpan.textContent = rpcHeight.toLocaleString();

                if (!isNaN(dbHeight) && !isNaN(rpcHeight) && rpcHeight > 0) {
                    const progress = ((dbHeight / rpcHeight) * 100);
                    progressBar.style.width = progress.toFixed(2) + '%';
                    progressBar.setAttribute('aria-valuenow', progress.toFixed(2));
                    progressBar.textContent = progress.toFixed(2) + '%';
                }

                if (dbHeight > lastHeight) {
                    const currentTime = Date.now();
                    addSpeedToHistory(dbHeight, currentTime);
                    lastSpeedCheck.lastBlockTime = currentTime;
                    updateUI();
                    lastHeight = dbHeight;
                    playSound('success');
                }

                appendOutput(`Processed block ${dbHeight.toLocaleString()} / ${rpcHeight.toLocaleString()}`);

                // Handle completion or continuation
                if (!autoContinueCheckbox.checked) {
                    appendOutput('Import paused. Click Start Import to continue.');
                    await performFullStop();
                    return;
                }

                if (dbHeight >= rpcHeight) {
                    appendOutput('Import cycle complete!');
                    playSound('success');
                    if (autoContinueCheckbox.checked && isRunning && !isStoppingRequested) {
                        appendOutput('Starting next cycle...');
                        await new Promise(resolve => setTimeout(resolve, 1000));
                        if (isRunning && !isStoppingRequested) {
                            updateProgress();
                        }
                    } else {
                        await performFullStop();
                    }
                } else if (isRunning && !isStoppingRequested) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                    updateProgress();
                }

            } catch (error) {
                console.error('Import error:', error);
                playSound('error');
                appendOutput('Error: ' + error.message);
                await performFullStop();
            }
        }

        async function performFullStop() {
            isRunning = false;
            isStoppingRequested = true;
            
            // Immediately update UI elements
            startBtn.disabled = false;
            stopBtn.disabled = true;
            
            // Immediately reset sync speed display
            syncSpeedElement.textContent = 'Stopped';
            syncSpeedElement.classList.remove('calculating', 'text-success', 'text-warning');
            syncEtaElement.textContent = '-';
            
            // Immediately clear intervals
            if (speedUpdateInterval) {
                clearInterval(speedUpdateInterval);
                speedUpdateInterval = null;
            }
            
            if (serverStatsInterval) {
                clearInterval(serverStatsInterval);
                serverStatsInterval = null;
            }
            
            if (cleanupInterval) {
                clearInterval(cleanupInterval);
                cleanupInterval = null;
            }
            
            // Immediately reset state variables
            speedHistory = [];
            hasSeenValidSpeed = false;
            
            // Immediately show stopped message
            appendOutput('Import stopped.');
            
            // Handle lock release in the background
            if (isLocked) {
                try {
                    const response = await fetch('import_blockchain_web.php?release_lock=1', {
                        headers: { 'X-Requested-With': 'XMLHttpRequest' }
                    });
                    
                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                    
                    const result = await response.json();
                    if (!result.success) {
                        throw new Error(result.error || 'Failed to release lock');
                    }
                    
                    isLocked = false;
                } catch (error) {
                    console.error('Failed to release lock:', error);
                    appendOutput('Warning: Failed to release lock - ' + error.message);
                }
            }
            
            isStoppingRequested = false;
        }

        // Add this state management for speed checks
        let speedCheckState = {
            controller: null,
            lastCheck: 0,
            minInterval: 2000, // Minimum time between checks
            failureCount: 0,
            maxFailures: 3,
            backoffMultiplier: 1.5,
            currentInterval: 2000
        };

        function fetchSpeedData() {
            if (!isRunning) return;

            const now = Date.now();
            if (now - speedCheckState.lastCheck < speedCheckState.minInterval) {
                return;
            }

            // Cleanup previous request if exists
            if (speedCheckState.controller) {
                speedCheckState.controller.abort();
            }

            speedCheckState.controller = new AbortController();
            speedCheckState.lastCheck = now;

            fetch(window.location.href + '?speed_check=1', {
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'Cache-Control': 'no-cache'
                },
                signal: speedCheckState.controller.signal
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                speedCheckState.failureCount = 0;
                speedCheckState.currentInterval = 2000; // Reset to default on success

                const currentTime = Date.now();
                const currentHeight = parseInt(dbHeightSpan.textContent.replace(/,/g, ''));
                const targetHeight = parseInt(rpcHeightSpan.textContent.replace(/,/g, ''));
                
                if (lastSpeedCheck.height > 0) {
                    const timeDiffMinutes = (currentTime - lastSpeedCheck.time) / 60000;
                    const blockDiff = currentHeight - lastSpeedCheck.height;
                    
                    if (blockDiff > 0 && timeDiffMinutes > 0) {
                        const instantSpeed = blockDiff / timeDiffMinutes;
                        addSpeedToHistory(instantSpeed);
                        lastSpeedCheck.lastBlockTime = currentTime;
                    }
                }

                lastSpeedCheck.time = currentTime;
                lastSpeedCheck.height = currentHeight;
                lastSpeedCheck.currentHeight = currentHeight;
                lastSpeedCheck.targetHeight = targetHeight;

                updateUI();
            })
            .catch(error => {
                if (error.name === 'AbortError') {
                    return; // Ignore aborted requests
                }

                console.error('Speed check error:', error);
                speedCheckState.failureCount++;

                // Implement exponential backoff
                if (speedCheckState.failureCount > 0) {
                    speedCheckState.currentInterval = Math.min(
                        10000, // Max interval of 10 seconds
                        speedCheckState.currentInterval * speedCheckState.backoffMultiplier
                    );
                }

                // If too many failures, update UI to show warning
                if (speedCheckState.failureCount >= speedCheckState.maxFailures) {
                    syncSpeedElement.textContent = 'Error';
                    syncSpeedElement.title = 'Speed check temporarily unavailable';
                    syncSpeedElement.classList.add('text-warning');
                    syncSpeedElement.classList.remove('text-success', 'calculating');
                }
            })
            .finally(() => {
                speedCheckState.controller = null;

                // Schedule next update with dynamic interval
                if (speedUpdateInterval) {
                    clearInterval(speedUpdateInterval);
                }
                speedUpdateInterval = setInterval(fetchSpeedData, speedCheckState.currentInterval);
            });
        }

        function updateUI() {
            if (!isRunning) return;

            const averageSpeed = calculateAverageSpeed();
            const currentTime = Date.now();
            const timeSinceLastBlock = (currentTime - lastSpeedCheck.lastBlockTime) / 1000;
            
            // Show speed if we have enough measurements
            if (speedHistory.length >= 2) {
                if (averageSpeed > 0) {
                    hasSeenValidSpeed = true;
                    syncSpeedElement.textContent = Math.round(averageSpeed);
                    syncSpeedElement.title = `Average over last ${speedHistory.length} samples`;
                    syncSpeedElement.classList.remove('calculating', 'text-warning');
                    syncSpeedElement.classList.add('text-success');
                    
                    // Play success sound when we first get a valid speed
                    if (!hasSeenValidSpeed) {
                        playSound('success');
                    }
                    
                    // Update ETA
                    const remainingBlocks = lastSpeedCheck.targetHeight - lastSpeedCheck.currentHeight;
                    const etaMinutes = remainingBlocks / averageSpeed;
                    syncEtaElement.textContent = formatETA(etaMinutes);
                    
                    // Only show warning if we haven't seen blocks for a while
                    if (timeSinceLastBlock > 30 && hasSeenValidSpeed) {
                        syncSpeedElement.textContent = 'Adjust settings';
                        syncSpeedElement.title = 'Try reducing batch size or increasing block delay';
                        syncSpeedElement.classList.add('text-warning');
                        syncSpeedElement.classList.remove('text-success');
                    }
                } else if (!hasSeenValidSpeed) {
                    // Only show "Calculating" if we've never seen a valid speed
                    syncSpeedElement.textContent = 'Calculating';
                    syncSpeedElement.classList.add('calculating');
                    syncSpeedElement.classList.remove('text-success', 'text-warning');
                }
            } else if (!hasSeenValidSpeed) {
                // Only show "Calculating" if we've never seen a valid speed
                syncSpeedElement.textContent = 'Calculating';
                syncSpeedElement.classList.add('calculating');
                syncSpeedElement.classList.remove('text-success', 'text-warning');
                syncEtaElement.textContent = '-';
            }
        }

        async function startImport() {
            // Disable button immediately to prevent multiple clicks
            startBtn.disabled = true;
            
            try {
                debugLog('Starting import process...');
                
                // Check if already locked first
                isLocked = await checkLock();
                debugLog('Lock check result:', isLocked);
                
                if (isLocked) {
                    appendOutput('Import is already running in another browser');
                    startBtn.disabled = false; // Re-enable button if we can't start
                    return;
                }

                // Try to acquire lock
                debugLog('Attempting to acquire lock...');
                const lockResponse = await fetch('import_blockchain_web.php?acquire_lock=1', {
                    headers: { 'X-Requested-With': 'XMLHttpRequest' }
                });
                
                const lockResult = await lockResponse.json();
                debugLog('Lock acquisition result:', lockResult);
                
                if (!lockResult.success) {
                    appendOutput('Failed to acquire lock: ' + (lockResult.error || 'Unknown error'));
                    startBtn.disabled = false; // Re-enable button if lock acquisition fails
                    return;
                }
                
                isLocked = true;
                isRunning = true;
                stopBtn.disabled = false;
                appendOutput('Starting blockchain import...');
                
                // Start the actual import process
                updateProgress();
                
                // Reset tracking for speed calculations
                lastSpeedCheck = {
                    time: Date.now(),
                    height: parseInt(dbHeightSpan.textContent.replace(/,/g, '')) || 0,
                    lastBlockTime: Date.now()
                };
                speedHistory = []; // Clear speed history
                hasSeenValidSpeed = false; // Reset the flag when starting new import
                
                // Show initial calculating state
                syncSpeedElement.textContent = 'Calculating';
                syncSpeedElement.classList.add('calculating');
                syncEtaElement.textContent = '-';
                
                // Start speed updates
                fetchSpeedData();
                
                // Set up intervals
                if (speedUpdateInterval) clearInterval(speedUpdateInterval);
                speedUpdateInterval = setInterval(fetchSpeedData, 2000);
                
                // Start server stats updates
                updateServerStats();
                serverStatsInterval = setInterval(updateServerStats, 5000);
                
                // Add periodic cleanup
                cleanupInterval = setInterval(() => {
                    speedHistory = speedHistory.slice(-settings.speedAverageWindow);
                    
                    // Force refresh of speed calculations
                    hasSeenValidSpeed = false;
                    updateUI();
                }, settings.cleanupInterval);
            } catch (error) {
                console.error('Start import failed:', error);
                playSound('error');
                appendOutput('Failed to start import: ' + error.message);
                isLocked = false;
                isRunning = false;
                startBtn.disabled = false;
                stopBtn.disabled = true;
            }
        }

        async function stopImport() {
            if (!isRunning || isStoppingRequested) return; // Add check for isStoppingRequested
            
            isStoppingRequested = true;
            isRunning = false;  // Add this line to immediately mark as not running
            stopBtn.disabled = true;
            
            appendOutput('Stopping import - waiting for current batch to complete...');
            
            try {
                if (timeoutId) {
                    clearTimeout(timeoutId);
                    timeoutId = null;
                }

                // Clear any pending operations
                if (speedUpdateInterval) {
                    clearInterval(speedUpdateInterval);
                    speedUpdateInterval = null;
                }
                
                if (serverStatsInterval) {
                    clearInterval(serverStatsInterval);
                    serverStatsInterval = null;
                }

                // Get final status before releasing lock
                try {
                    const statusResponse = await fetch(window.location.href + '?final_status=1', {
                        headers: { 'X-Requested-With': 'XMLHttpRequest' }
                    });
                    
                    if (statusResponse.ok) {
                        const data = await statusResponse.json();
                        const dbHeight = parseInt(data.after.height);
                        const rpcHeight = parseInt(data.current_height);
                        
                        dbHeightSpan.textContent = dbHeight.toLocaleString();
                        rpcHeightSpan.textContent = rpcHeight.toLocaleString();
                        
                        if (!isNaN(dbHeight) && !isNaN(rpcHeight) && rpcHeight > 0) {
                            const progress = ((dbHeight / rpcHeight) * 100);
                            progressBar.style.width = progress.toFixed(2) + '%';
                            progressBar.setAttribute('aria-valuenow', progress.toFixed(2));
                            progressBar.textContent = progress.toFixed(2) + '%';
                        }
                    }
                } catch (error) {
                    console.error('Failed to get final status:', error);
                }

                // Release the lock
                if (isLocked) {
                    const response = await fetch('import_blockchain_web.php?release_lock=1', {
                        headers: { 'X-Requested-With': 'XMLHttpRequest' }
                    });
                    
                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                    
                    const result = await response.json();
                    if (!result.success) {
                        throw new Error(result.error || 'Failed to release lock');
                    }
                    
                    isLocked = false;
                }
                
                // Reset UI and state
                speedHistory = [];
                syncSpeedElement.textContent = 'Stopped';
                syncSpeedElement.title = ''; // Clear any tooltip
                syncSpeedElement.classList.remove('calculating', 'text-success', 'text-warning');
                syncEtaElement.textContent = '-';
                hasSeenValidSpeed = false;
                
                // Only append "Import stopped" if it was explicitly requested
                if (isStoppingRequested) {
                    appendOutput('Import stopped.');
                }
                
                startBtn.disabled = false;
                
            } catch (error) {
                console.error('Failed to stop import:', error);
                playSound('error');
                appendOutput('Error stopping import: ' + error.message);
                
                isRunning = false;
                isLocked = false;
                startBtn.disabled = false;
                
                if (timeoutId) clearTimeout(timeoutId);
                if (speedUpdateInterval) clearInterval(speedUpdateInterval);
                if (serverStatsInterval) clearInterval(serverStatsInterval);
            } finally {
                isStoppingRequested = false;
            }
        }

        function formatETA(minutes) {
            if (minutes < 1) return 'less than a minute';
            if (minutes < 60) return Math.round(minutes) + ' minutes';
            
            const hours = Math.floor(minutes / 60);
            const remainingMinutes = Math.round(minutes % 60);
            
            if (hours < 24) {
                return `${hours}h ${remainingMinutes}m`;
            }
            
            const days = Math.floor(hours / 24);
            const remainingHours = hours % 24;
            return `${days}d ${remainingHours}h`;
        }

        startBtn.addEventListener('click', () => {
            // Disable immediately on click
            startBtn.disabled = true;
            startImport().catch(error => {
                console.error('Error in startImport:', error);
                startBtn.disabled = false; // Re-enable on error
            });
        });
        stopBtn.addEventListener('click', stopImport);
        // Load settings when page loads
        document.addEventListener('DOMContentLoaded', loadSettings);

        // Add validation for the speedAverageWindow input
        document.getElementById('speedAverageWindowInput').addEventListener('input', function() {
            const value = parseInt(this.value);
            if (value < 1) this.value = 1;
            if (value > 20) this.value = 20;
        });

        // Add validation for the new inputs
        document.getElementById('maxRetryAttemptsInput').addEventListener('input', function() {
            const value = parseInt(this.value);
            if (value < 1) this.value = 1;
            if (value > 10) this.value = 10;
        });

        document.getElementById('retryDelayInput').addEventListener('input', function() {
            const value = parseInt(this.value);
            if (value < 500) this.value = 500;
            if (value > 5000) this.value = 5000;
        });

        // Add this with your other event listeners
document.getElementById('rpcBatchSizeInput').addEventListener('input', function() {
    document.getElementById('rpcBatchValue').textContent = this.value;
});

        let serverStatsInterval;
        function startServerStatsUpdates() {
            if (serverStatsInterval) {
                clearInterval(serverStatsInterval);
            }
            updateServerStats(); // Initial update
            serverStatsInterval = setInterval(updateServerStats, 5000); // Increased interval to 5 seconds
        }

        function cleanupCurrentRequest() {
            if (window.currentStatsRequest) {
                window.currentStatsRequest.abort();
                window.currentStatsRequest = null;
            }
        }

        function updateServerStats() {
            if (!isRunning) return;

            // Cleanup any pending request
            cleanupCurrentRequest();

            // Create new AbortController for this request
            window.currentStatsRequest = new AbortController();

            fetch(window.location.href + '?server_stats=1', {
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'Cache-Control': 'no-cache'
                },
                signal: window.currentStatsRequest.signal
            })
            .then(response => handleFetchError(response))
            .then(response => response.json())
            .then(data => {
                // Safely update load average
                const loadElement = document.getElementById('server-load');
                if (loadElement) {
                    loadElement.textContent = (data.load != null) ? 
                        Number(data.load).toFixed(2) : 
                        'N/A';
                }
                
                // Safely update IO wait
                const ioWaitElement = document.getElementById('io-wait');
                if (ioWaitElement) {
                    ioWaitElement.textContent = (data.iowait != null) ? 
                        Number(data.iowait).toFixed(2) : 
                        'N/A';
                }
            })
            .catch(error => {
                if (error.name === 'AbortError') return;
                
                console.warn('Server stats error:', error);
                
                // Set fallback values on error
                const loadElement = document.getElementById('server-load');
                const ioWaitElement = document.getElementById('io-wait');
                
                if (loadElement) loadElement.textContent = 'N/A';
                if (ioWaitElement) ioWaitElement.textContent = 'N/A';
            })
            .finally(() => {
                window.currentStatsRequest = null;
            });
        }

        // Update the DOMContentLoaded handler
        document.addEventListener('DOMContentLoaded', function() {
            updateServerStats(); // Initial check for available stats
        });

        // Update the volume slider event listener to use 'input' event
        document.getElementById('soundVolumeInput').addEventListener('input', function() {
            const volumeValue = this.value;
            document.getElementById('volumeValue').textContent = volumeValue;
            // Optionally, update the settings in real-time
            settings.soundVolume = volumeValue / 100;
        });

        // Add this function to initialize UI elements
        function initializeUI() {
            // Set initial volume display
            const volumeSlider = document.getElementById('soundVolumeInput'); // Changed from 'soundVolume' to 'soundVolumeInput'
            const volumeDisplay = document.getElementById('volumeValue');
            volumeDisplay.textContent = volumeSlider.value;

            // Other UI initialization code...
        }

        // Call initializeUI when the document is ready
        document.addEventListener('DOMContentLoaded', function() {
            initializeUI();
            loadSettings();
            // Other initialization code...
        });
        document.addEventListener('DOMContentLoaded', function() {
    // Override Bootstrap's modal handling
    if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
        const originalShow = bootstrap.Modal.prototype.show;
        const originalHide = bootstrap.Modal.prototype.hide;

        bootstrap.Modal.prototype.show = function() {
            // Remove any existing aria-hidden attributes
            document.querySelectorAll('[aria-hidden]').forEach(el => {
                el.removeAttribute('aria-hidden');
            });

            // Add inert attribute to all root-level elements except the modal
            document.querySelectorAll('body > *').forEach(el => {
                if (!el.classList.contains('modal') && !el.classList.contains('modal-backdrop')) {
                    el.setAttribute('inert', '');
                }
            });

            return originalShow.apply(this, arguments);
        };

        bootstrap.Modal.prototype.hide = function() {
            // Remove inert attribute from all elements when modal closes
            document.querySelectorAll('[inert]').forEach(el => {
                el.removeAttribute('inert');
            });

            return originalHide.apply(this, arguments);
        };
    }

    // Initialize modals with proper focus management
    document.querySelectorAll('.modal').forEach(modalElement => {
        modalElement.addEventListener('shown.bs.modal', () => {
            const focusableElements = modalElement.querySelectorAll(
                'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
            );
            if (focusableElements.length) {
                focusableElements[0].focus();
            }
        });

        modalElement.addEventListener('show.bs.modal', (event) => {
            modalElement._returnFocus = event.relatedTarget;
        });

        modalElement.addEventListener('hidden.bs.modal', () => {
            if (modalElement._returnFocus) {
                modalElement._returnFocus.focus();
            }
        });
    });
});
        
        </script>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    <?php
    exit;
}

// Protect AJAX endpoints
if ($isAjax && !isset($_SESSION['authenticated'])) {
    header('HTTP/1.1 401 Unauthorized');
    echo json_encode(['success' => false, 'error' => 'Not authenticated']);
    exit;
}

// Handle AJAX request
try {
    // Ensure clean output buffer
    while (ob_get_level()) ob_end_clean();
    
    // Set proper headers
    header('Content-Type: application/json');
    header('X-Content-Type-Options: nosniff');
    
    if ($isAjax) {
        // Master reset endpoint
        if (isset($_GET['master_reset'])) {
            try {
                // Kill any running PHP processes related to the importer
                $processFiles = glob(__DIR__ . '/*.lock');
                foreach ($processFiles as $file) {
                    @unlink($file);
                }
                
                // Wait briefly for processes to notice lock files are gone
                sleep(1);
                
                require_once __DIR__ . '/BlockchainImporter.php';
                $importer = new BlockchainImporter();
                
                // Perform the reset
                $success = $importer->resetDatabase();
                
                if (!$success) {
                    throw new Exception("Database reset failed");
                }
                
                // Delete config file
                $configFile = __DIR__ . '/importer.conf';
                if (file_exists($configFile)) {
                    if (!@unlink($configFile)) {
                        error_log("Failed to delete config file: $configFile");
                    }
                }
                
                // Clear session
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

        // Continue with existing endpoints...
        if (isset($_GET['check_lock'])) {
            $locked = file_exists(LOCK_FILE);
            $pid = $locked ? @file_get_contents(LOCK_FILE) : null;
            
            if ($locked && $pid && function_exists('posix_kill')) {
                $locked = @posix_kill($pid, 0);
                if (!$locked) {
                    @unlink(LOCK_FILE);
                }
            }
            
            echo json_encode([
                'locked' => $locked,
                'pid' => $pid
            ]);
            exit;
        }

        if (isset($_GET['acquire_lock'])) {
            $permCheck = checkLockFilePermissions();
            if (!$permCheck['success']) {
                echo json_encode(['success' => false, 'error' => $permCheck['error']]);
                exit;
            }

            if (file_exists(LOCK_FILE)) {
                $pid = @file_get_contents(LOCK_FILE);
                if ($pid && function_exists('posix_kill') && @posix_kill($pid, 0)) {
                    echo json_encode(['success' => false, 'error' => 'Import already running']);
                    exit;
                }
                @unlink(LOCK_FILE);
            }

            $currentPid = getmypid();
            if ($currentPid === false) {
                echo json_encode(['success' => false, 'error' => 'Failed to get process ID']);
                exit;
            }

            if (file_put_contents(LOCK_FILE, $currentPid) === false) {
                $error = error_get_last();
                echo json_encode(['success' => false, 'error' => 'Failed to create lock file: ' . ($error['message'] ?? 'Unknown error')]);
                exit;
            }

            echo json_encode(['success' => true]);
            exit;
        }

        if (isset($_GET['release_lock'])) {
            if (file_exists(LOCK_FILE)) {
                if (@unlink(LOCK_FILE)) {
                    echo json_encode(['success' => true]);
                } else {
                    echo json_encode(['success' => false, 'error' => 'Failed to delete lock file']);
                }
            } else {
                echo json_encode(['success' => true]);
            }
            exit;
        }

        if ($isAjax && isset($_GET['server_stats'])) {
            // Ensure clean output buffer
            while (ob_get_level()) ob_end_clean();
            
            $stats = ['load' => 0, 'iowait' => null];
            
            // Get load average
            $load = sys_getloadavg();
            $stats['load'] = $load[0];
            
            // Get IO wait using iostat
            if (function_exists('shell_exec')) {
                $raw_output = shell_exec("iostat -c 1 2 2>/dev/null");
                
                if ($raw_output !== null) {
                    $lines = explode("\n", trim($raw_output));
                    
                    // Get the last valid line
                    $last_line = null;
                    foreach (array_reverse($lines) as $line) {
                        if (preg_match('/^\s*[\d.]+/', $line)) {
                            $last_line = $line;
                            break;
                        }
                    }
                    
                    if ($last_line) {
                        // Split and clean the line
                        $values = array_values(array_filter(preg_split('/\s+/', trim($last_line))));
                        
                        // iowait should be the 4th value (index 3)
                        if (isset($values[3]) && is_numeric($values[3])) {
                            $iowait = floatval($values[3]);
                            
                            // Only set if we got a valid value
                            if ($iowait !== false && $iowait >= 0) {
                                $stats['iowait'] = round($iowait, 2); // Changed to 2 decimal places
                                
                                // Add debug info
                                $stats['debug'] = [
                                    'raw_line' => $last_line,
                                    'parsed_values' => $values,
                                    'iowait_raw' => $iowait
                                ];
                            }
                        }
                    }
                }
            }
            
            header('Content-Type: application/json');
            echo json_encode($stats);
            exit;
        }
    }

    // Speed check endpoint
    if ($isAjax && isset($_GET['speed_check'])) {
        require_once __DIR__ . '/BlockchainImporter.php';
        $importer = new BlockchainImporter();
        $status = $importer->getStatus();
        
        // Get the current timestamp and height
        $currentTime = time();
        $currentHeight = $status['last_imported_height'];
        
        // Initialize or get session data
        if (!isset($_SESSION['speed_stats'])) {
            $_SESSION['speed_stats'] = [
                'last_check_time' => $currentTime,
                'last_check_height' => $currentHeight,
                'speed_history' => []
            ];
        }
        
        // Calculate speed only if we have previous data
        $timeDiff = $currentTime - $_SESSION['speed_stats']['last_check_time'];
        $heightDiff = $currentHeight - $_SESSION['speed_stats']['last_check_height'];
        
        // Update session with current values
        $_SESSION['speed_stats']['last_check_time'] = $currentTime;
        $_SESSION['speed_stats']['last_check_height'] = $currentHeight;
        
        // Limit size of speed history in session
        if (isset($_SESSION['speed_stats']['speed_history'])) {
            $_SESSION['speed_stats']['speed_history'] = array_slice(
                $_SESSION['speed_stats']['speed_history'], 
                -50  // Keep only last 50 entries
            );
        }
        
        // Periodically clean old session data
        if (rand(1, 100) === 1) {  // 1% chance each request
            session_gc();
        }
        
        echo json_encode([
            'success' => true,
            'current_height' => $currentHeight,
            'target_height' => $status['current_height'],
            'timestamp' => $currentTime
        ]);
        exit;
    }

    // Master reset endpoint
    if ($isAjax && isset($_GET['master_reset'])) {
        try {
            require_once __DIR__ . '/BlockchainImporter.php';
            $importer = new BlockchainImporter();
            
            // Drop all tables
            $importer->db->exec("DROP TABLE IF EXISTS address_balances");
            $importer->db->exec("DROP TABLE IF EXISTS blocks");
            $importer->db->exec("DROP TABLE IF EXISTS transactions");
            $importer->db->exec("DROP TABLE IF EXISTS tx_outputs");
            $importer->db->exec("DROP TABLE IF EXISTS tx_inputs");
            
            // Delete config file
            $configFile = __DIR__ . '/config.php';
            if (file_exists($configFile)) {
                unlink($configFile);
            }
            
            // Clear session
            session_destroy();
            
            echo json_encode(['success' => true]);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage()
            ]);
        }
        exit;
    }

    require_once __DIR__ . '/BlockchainImporter.php';
    
    $importer = new BlockchainImporter();
    
    // Set batch size if provided
    if (isset($_GET['batch_size'])) {
        $batchSize = (int)$_GET['batch_size'];
        $importer->setMaxBlocksPerRun($batchSize);
    }

    // Add block delay if provided
    if (isset($_GET['block_delay'])) {
        $blockDelay = (int)$_GET['block_delay'];
        $importer->setBlockDelay($blockDelay);
    }

    // Set RPC batch size if provided
    if (isset($_GET['rpc_batch_size'])) {
        $rpcBatchSize = (int)$_GET['rpc_batch_size'];
        if ($rpcBatchSize >= 1 && $rpcBatchSize <= 2000) {
            $importer->setMaxRpcBatchSize($rpcBatchSize);
        }
    }
    
    $status = $importer->getStatus();
    $importResult = $importer->import();
    $newStatus = $importer->getStatus();
    
    // Ensure proper JSON encoding
    $response = array_merge($importResult ?? [], [
        'before' => [
            'height' => $status['last_imported_height'],
            'progress' => isset($status['import_progress']) ? (float)$status['import_progress'] : 0
        ],
        'after' => [
            'height' => $newStatus['last_imported_height'],
            'progress' => $newStatus['import_progress']
        ],
        'blockchain_height' => $newStatus['current_height'],
        'status' => ($newStatus['last_imported_height'] >= $newStatus['current_height']) ? 'up_to_date' : 'importing'
    ]);
    
    // Ensure no other output has corrupted our JSON
    echo json_encode($response, JSON_THROW_ON_ERROR);
    
} catch (Exception $e) {
    error_log("Blockchain import error: " . $e->getMessage());
    http_response_code(500);
    
    // Ensure clean output buffer
    while (ob_get_level()) ob_end_clean();
    
    header('Content-Type: application/json');
    echo json_encode([
        'error' => $e->getMessage(),
        'status' => 'error'
    ], JSON_THROW_ON_ERROR);
}

/**
 * Cleanup Handler
 * Ensures lock file is removed when script terminates
 */
register_shutdown_function(function() {
    if (file_exists(LOCK_FILE)) {
        @unlink(LOCK_FILE);
    }
});
