<?php
declare(strict_types=1);

ini_set('max_execution_time', '0');     // Remove PHP timeout limit
set_time_limit(0);                      // Alternative method for some systems
ini_set('memory_limit', '1G');          // Increase memory limit if needed
if (!defined('IN_SCRIPT')) {
    define("IN_SCRIPT", true);
}
/**
 * Modern Bitcoin RPC Client
 * Optimized for PHP 7.4+ with type declarations, improved error handling,
 * connection pooling, and batch request support
 */
class BitcoinRPC {
    private string $username;
    private string $password;
    private string $host;
    private int $port;
    private string $url;
    private bool $useSSL;
    private ?string $caCertificate;
    private $batch = [];
    private $batchMap = [];
    
    // Connection handling
    /** @var resource|CurlHandle|null */
    private $curlHandle = null;
    private array $curlOptions = [];
    private int $connectionTimeout = 120;  // Increased from 30
    private int $requestTimeout = 300;     // Increased from 60
    private int $maxRetries = 3;
    private int $retryDelay = 1000; // milliseconds
    
    // Request tracking
    private int $id = 0;
    public ?int $status = null;
    public ?string $error = null;
    public ?string $rawResponse = null;
    public ?array $response = null;
    
    // Batch processing
    private array $batchRequests = [];
    private int $maxBatchSize = 100;
    
    /**
     * @param string $username RPC username
     * @param string $password RPC password
     * @param string $host RPC host
     * @param int $port RPC port
     * @param string|null $url Custom URL path
     * @throws InvalidArgumentException
     */
    public function __construct(
        string $username,
        string $password,
        string $host = 'localhost',
        int $port = 8332,
        ?string $url = null,
        bool $useSSL = false
    ) {
        $this->username = $username;
        $this->password = $password;
        $this->host = $host;
        $this->port = $port;
        $this->url = $url ?? '';
        $this->useSSL = $useSSL;
        $this->caCertificate = null;
        
        $this->initializeCurl();
    }
    
    /**
     * Initialize curl with default options
     * @throws RuntimeException if curl initialization fails
     */
    private function initializeCurl(): void {
        // Create new curl handle if none exists
        if (!$this->curlHandle) {
            $this->curlHandle = curl_init();
            if ($this->curlHandle === false) {
                throw new RuntimeException("Failed to initialize CURL");
            }
        }

        $protocol = $this->useSSL ? 'https' : 'http';
        $baseUrl = "{$protocol}://{$this->host}:{$this->port}/{$this->url}";
        
        $this->curlOptions = [
            CURLOPT_URL => $baseUrl,
            CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
            CURLOPT_USERPWD => "{$this->username}:{$this->password}",
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
            CURLOPT_POST => true,
            CURLOPT_CONNECTTIMEOUT => $this->connectionTimeout,
            CURLOPT_TIMEOUT => $this->requestTimeout,
            CURLOPT_TCP_KEEPALIVE => 1,
            CURLOPT_TCP_KEEPIDLE => 60,
            CURLOPT_TCP_NODELAY => 1,
        ];
        
        if ($this->useSSL) {
            if ($this->caCertificate) {
                $this->curlOptions[CURLOPT_CAINFO] = $this->caCertificate;
                $this->curlOptions[CURLOPT_CAPATH] = dirname($this->caCertificate);
            } else {
                $this->curlOptions[CURLOPT_SSL_VERIFYPEER] = false;
                $this->curlOptions[CURLOPT_SSL_VERIFYHOST] = 0;
            }
        }

        // Apply all curl options
        foreach ($this->curlOptions as $option => $value) {
            if (curl_setopt($this->curlHandle, $option, $value) === false) {
                throw new RuntimeException("Failed to set CURL option: " . $option);
            }
        }
    }
    
    /**
     * Set SSL certificate for secure connections
     */
    public function setSSL(?string $certificate = null): void {
        $this->useSSL = false;
        $this->caCertificate = $certificate;
        $this->initializeCurl();
    }
    
    /**
     * Configure connection timeouts
     */
    public function setTimeouts(int $connectionTimeout, int $requestTimeout): void {
        $this->connectionTimeout = $connectionTimeout;
        $this->requestTimeout = $requestTimeout;
        $this->curlOptions[CURLOPT_CONNECTTIMEOUT] = $connectionTimeout;
        $this->curlOptions[CURLOPT_TIMEOUT] = $requestTimeout;
    }
    
    /**
     * Add a request to the batch queue
     * @param string $method RPC method name
     * @param array $params Parameters for the method
     * @throws RuntimeException if batch size limit is reached
     */
    public function addToBatch(string $method, array $params = []): void {
        if (count($this->batchRequests) >= $this->maxBatchSize) {
            throw new RuntimeException("Batch size limit reached");
        }
        
        $this->batchRequests[] = [
            'jsonrpc' => '2.0',
            'method' => $method,
            'params' => $params,
            'id' => ++$this->id
        ];
    }
    
    /**
     * Execute all queued batch requests
     * @return array
     * @throws RuntimeException
     */
    public function executeBatch(): array {
        if (empty($this->batchRequests)) {
            return [];  // Return empty array instead of null when no requests
        }
        
        try {
            $result = $this->executeRequest($this->batchRequests);
            
            // Reset batch requests
            $this->batchRequests = [];
            
            // Ensure we always return an array
            if (!is_array($result)) {
                throw new RuntimeException("RPC batch execution failed: Invalid response format");
            }
            
            // Extract 'result' from each response
            $results = [];
            foreach ($result as $response) {
                if (isset($response['error']) && $response['error'] !== null) {
                    throw new RuntimeException("RPC Error: " . ($response['error']['message'] ?? 'Unknown error'));
                }
                $results[] = $response['result'] ?? null;
            }
            
            return $results;
        } catch (Exception $e) {
            $this->batchRequests = []; // Clear batch on error
            throw new RuntimeException("Batch execution failed: " . $e->getMessage());
        }
    }
    
    /**
     * Magic method to handle RPC calls
     * @param string $method
     * @param array $params
     * @return mixed
     * @throws RuntimeException
     */
    public function __call($method, $params) {
        try {
            $request = [
                'method' => $method,           // Removed 'jsonrpc': '2.0'
                'params' => $params[0] ?? [],
                'id' => ++$this->id
            ];

            $response = $this->executeRequest($request);
            
            if (!is_array($response)) {
                throw new RuntimeException("Invalid RPC response format");
            }

            // Check for error first
            if (isset($response['error']) && $response['error'] !== null) {
                $errorMessage = is_array($response['error']) ? 
                    ($response['error']['message'] ?? json_encode($response['error'])) : 
                    $response['error'];
                throw new RuntimeException("RPC Error: " . $errorMessage);
            }

            // Return result directly if it exists
            if (isset($response['result'])) {
                return $response['result'];
            }

            // If no result but also no error, return the whole response
            return $response;
        } catch (Exception $e) {
            error_log("RPC call error ({$method}): " . $e->getMessage());
            throw new RuntimeException("RPC call failed: " . $e->getMessage());
        }
    }
    
    /**
     * Execute a request and handle the response
     * @param array|array[] $request Single request or batch of requests
     * @return array|mixed Response data
     * @throws RuntimeException
     */
    private function executeRequest($request) {
        try {
            $this->initializeCurl();
            
            $postData = json_encode($request);
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new RuntimeException("Failed to encode request: " . json_last_error_msg());
            }
            
            if (curl_setopt($this->curlHandle, CURLOPT_POSTFIELDS, $postData) === false) {
                throw new RuntimeException("Failed to set CURL POST data");
            }
            
            $attempts = 0;
            $lastError = null;
            
            while ($attempts < $this->maxRetries) {
                $this->rawResponse = curl_exec($this->curlHandle);
                if ($this->rawResponse !== false) {
                    $this->status = curl_getinfo($this->curlHandle, CURLINFO_HTTP_CODE);
                    
                    if ($this->status === 200) {
                        $response = json_decode($this->rawResponse, true);
                        if (json_last_error() === JSON_ERROR_NONE) {
                            return $response;
                        }
                        $lastError = "Failed to decode response: " . json_last_error_msg();
                    } else {
                        $lastError = "HTTP Error: " . $this->status;
                    }
                } else {
                    $lastError = "CURL Error: " . curl_error($this->curlHandle);
                }
                
                $attempts++;
                if ($attempts < $this->maxRetries) {
                    usleep($this->retryDelay * 1000);
                    $this->initializeCurl(); // Reinitialize curl for retry
                }
            }
            
            throw new RuntimeException($lastError);
        } catch (Exception $e) {
            if ($this->curlHandle) {
                curl_close($this->curlHandle);
                $this->curlHandle = null;
            }
            throw $e;
        }
    }
    
    /**
     * Handle HTTP error responses
     * @throws RuntimeException
     */
    private function handleHttpError(): void {
        $errorMessages = [
            400 => 'Bad Request',
            401 => 'Unauthorized',
            403 => 'Forbidden',
            404 => 'Not Found',
            500 => 'Internal Server Error',
            502 => 'Bad Gateway',
            503 => 'Service Unavailable',
            504 => 'Gateway Timeout'
        ];
        
        $message = $errorMessages[$this->status] ?? 'Unknown Error';
        throw new RuntimeException("HTTP {$this->status}: {$message}");
    }
    
    /**
     * Clean up resources
     */
    public function __destruct() {
        if ($this->curlHandle) {
            curl_close($this->curlHandle);
            $this->curlHandle = null;
        }
    }
    public function clearBatch() {
        $this->batch = [];
        $this->batchMap = [];
    }
}