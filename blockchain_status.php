<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);
define("IN_SCRIPT", true);

header('Content-Type: text/html; charset=utf-8');

try {
    require_once __DIR__ . '/BlockchainImporter.php';
    
    $importer = new BlockchainImporter();
    $status = $importer->getStatus();
    
    ?>
    <!DOCTYPE html>
    <html lang="en" data-bs-theme="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Blockchain Status</title>
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
            
            .card {
                background-color: #2c3338;
                border-color: #444;
            }
            
            .progress {
                height: 25px;
                background-color: #2c3338;
            }
            
            .text-muted {
                color: #8f959b !important;
            }
            
            .table {
                color: var(--bs-body-color);
            }
            
            .table th {
                color: #8f959b;
            }
            
            .card-header {
                background-color: rgba(0, 0, 0, 0.2);
                border-bottom-color: #444;
            }
            
            .btn-primary {
                background-color: #0d6efd;
                border-color: #0d6efd;
            }
            
            .btn-primary:hover {
                background-color: #0b5ed7;
                border-color: #0a58ca;
            }
        </style>
    </head>
    <body>
        <div class="container mt-5">
            <h1>Blockchain Status</h1>
            
            <!-- RPC Node Status -->
            <div class="card mt-4">
                <div class="card-header">
                    <h5 class="mb-0">RPC Node Status</h5>
                </div>
                <div class="card-body">
                    <table class="table">
                        <tbody>
                            <tr>
                                <th>Current Block Height:</th>
                                <td><?php echo number_format($status['current_height']); ?></td>
                            </tr>
                            <tr>
                                <th>Headers:</th>
                                <td><?php echo number_format($status['headers']); ?></td>
                            </tr>
                            <tr>
                                <th>Difficulty:</th>
                                <td><?php echo number_format($status['difficulty'], 8); ?></td>
                            </tr>
                            <tr>
                                <th>Chain:</th>
                                <td><?php echo htmlspecialchars($status['chain']); ?></td>
                            </tr>
                            <tr>
                                <th>Node Sync Progress:</th>
                                <td>
                                    <div class="progress">
                                        <div class="progress-bar progress-bar-striped progress-bar-animated" 
                                             role="progressbar" 
                                             style="width: <?php echo number_format($status['verification_progress'] * 100, 2); ?>%">
                                            <?php echo number_format($status['verification_progress'] * 100, 2); ?>%
                                        </div>
                                    </div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Database Import Status -->
            <div class="card mt-4">
                <div class="card-header">
                    <h5 class="mb-0">Database Import Status</h5>
                </div>
                <div class="card-body">
                    <table class="table">
                        <tbody>
                            <tr>
                                <th>Imported Blocks:</th>
                                <td><?php echo number_format($status['imported_blocks']); ?></td>
                            </tr>
                            <tr>
                                <th>Last Imported Height:</th>
                                <td><?php echo number_format($status['last_imported_height']); ?></td>
                            </tr>
                            <tr>
                                <th>Import Progress:</th>
                                <td>
                                    <div class="progress">
                                        <div class="progress-bar bg-success progress-bar-striped progress-bar-animated" 
                                             role="progressbar" 
                                             style="width: <?php echo number_format($status['import_progress'], 2); ?>%">
                                            <?php echo number_format($status['import_progress'], 2); ?>%
                                        </div>
                                    </div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div class="mt-4">
                <a href="/" class="btn btn-primary">Back to Explorer</a>
            </div>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    <?php
    
} catch (Exception $e) {
    ?>
    <div class="container mt-5">
        <div class="alert alert-danger">
            <h4>Error</h4>
            <p><?php echo htmlspecialchars($e->getMessage()); ?></p>
        </div>
        <a href="/" class="btn btn-primary">Back to Explorer</a>
    </div>
    <?php
}
