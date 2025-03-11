<?php
if (!defined('IN_SCRIPT')) {
    die('Direct access not permitted');
}

class Config {
    private static $instance = null;
    private $config = [];
    
    private function __construct() {
        $configPath = __DIR__ . '/importer.conf';
        
        // Allow empty config for initial setup
        if (!file_exists($configPath)) {
            $this->config = [];
            return;
        }
        
        if (!is_readable($configPath)) {
            throw new Exception("Configuration file is not readable at: " . $configPath);
        }
        
        // Add error handling for parse_ini_file
        $this->config = @parse_ini_file($configPath, false, INI_SCANNER_RAW);
        if ($this->config === false) {
            $error = error_get_last();
            throw new Exception(
                "Failed to parse configuration file at: " . $configPath . 
                "\nError: " . ($error['message'] ?? 'Unknown error')
            );
        }

        // Strip quotes from values if present
        foreach ($this->config as $key => $value) {
            if (is_string($value)) {
                $this->config[$key] = trim($value, '"\'');
            }
        }
    }
    
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    public function get($key, $default = null) {
        return isset($this->config[$key]) ? $this->config[$key] : $default;
    }
    
    public function getAll() {
        return $this->config;
    }

    public function isConfigured() {
        $requiredKeys = [
            'DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASS',
            'RPC_USER', 'RPC_PASSWORD', 'RPC_HOST', 'RPC_PORT'
        ];
        
        foreach ($requiredKeys as $key) {
            if (!isset($this->config[$key])) {
                return false;
            }
        }
        return true;
    }
}
