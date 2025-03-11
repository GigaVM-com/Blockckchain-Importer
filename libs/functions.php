<?php
/**
 * Common utility functions for the blockchain importer
 */

function formatBytes($bytes, $precision = 2) {
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    return round($bytes / pow(1024, $pow), $precision) . ' ' . $units[$pow];
}

function getSystemLoad() {
    if (function_exists('sys_getloadavg')) {
        $load = sys_getloadavg();
        return $load[0];
    }
    return false;
}

function getMemoryUsage() {
    return memory_get_usage(true);
}

function getIOWait() {
    if (PHP_OS !== 'Linux') {
        return false;
    }
    
    $stat = @file_get_contents('/proc/stat');
    if ($stat === false) {
        return false;
    }
    
    $lines = explode("\n", $stat);
    foreach ($lines as $line) {
        if (strpos($line, 'cpu ') === 0) {
            $values = array_slice(explode(' ', trim($line)), 1);
            if (isset($values[4])) {
                $total = array_sum($values);
                return ($values[4] / $total) * 100;
            }
        }
    }
    
    return false;
}