<?php
//session_start();

class CallApi {
    private $curl;
    private $url;
    private $options;
     
    function __construct($url) {
        if (!extension_loaded("curl")) {
            throw new Exception("cURL extension not loaded!");
        }
        
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            throw new InvalidArgumentException("Invalid URL provided");
        }
        
        $this->curl = curl_init();
        $this->url = rtrim($url, '/');
        
        // Default options
        $this->options = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FAILONERROR => false,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Accept: application/json'
            ]
        ];
    }

    function __destruct() {
        if (is_resource($this->curl)) {
            curl_close($this->curl);
        }
    }

    private function setCommonOptions() {
        curl_setopt_array($this->curl, $this->options);
        curl_setopt($this->curl, CURLOPT_HTTPGET, true);
    }

    private function executeRequest() {
        $response = curl_exec($this->curl);
        
        if ($response === false) {
            $error = curl_error($this->curl);
            $errno = curl_errno($this->curl);
            throw new Exception("cURL error ($errno): $error");
        }
        
        $httpCode = curl_getinfo($this->curl, CURLINFO_HTTP_CODE);
        
        if ($httpCode >= 400) {
            throw new Exception("HTTP error: $httpCode - " . $response);
        }
        
        return $response;
    }

    public function get_all_implants() {
        $this->setCommonOptions();
        curl_setopt($this->curl, CURLOPT_URL, $this->url . "/api/implants");
        
        return $this->executeRequest();
    }

    public function get_all_tasks() {
        $this->setCommonOptions();
        curl_setopt($this->curl, CURLOPT_URL, $this->url . "/api/tasks");
        
        return $this->executeRequest();
    }

    public function auth($username, $password) {
        $this->setCommonOptions();
        #curl_setopt($this->curl, CURLOPT_HTTPPOST, true);
        $_POST['Username'] = $username;
        $_POST['Password'] = $password;
        
        curl_setopt($this->curl, CURLOPT_URL, $this->url . "/api/auth");
        return $this->executeRequest;
    }

    public function getLastHttpCode() {
        return curl_getinfo($this->curl, CURLINFO_HTTP_CODE);
    }

    public function getLastError() {
        return [
            'error' => curl_error($this->curl),
            'errno' => curl_errno($this->curl)
        ];
    }
}

?>
