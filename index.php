<?php
/**
 * HopTransfert
 * A minimalist, single-file, secure PHP application for anonymous file sharing
 * 
 * @author Fedir RYKHTIK; acclerated development with Claude.AI
 * @version 1.0
 * @requires PHP 8.1+
 */

// =============================================================================
// CONFIGURATION CONSTANTS
// =============================================================================

// Rate limiting
const DOWNLOAD_RATE_LIMIT_SECONDS = 60;

// File and directory paths
const DATA_DIR = __DIR__ . '/data';
const DOWNLOAD_DIR = __DIR__ . '/download';
const FILES_JSON = DATA_DIR . '/files.json';
const DOWNLOAD_LOG = DATA_DIR . '/download.log';
const ERROR_LOG = DATA_DIR . '/php_errors.log';

// File upload limits
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
const ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'txt', 'doc', 'docx', 'zip', 'rar'];

// Security
const PASSWORD_MIN_LENGTH = 6;

// =============================================================================
// ERROR HANDLING SETUP
// =============================================================================

// Configure error logging
ini_set('log_errors', 1);
ini_set('error_log', ERROR_LOG);
ini_set('display_errors', 0);

// Custom error handler
set_error_handler(function($severity, $message, $file, $line) {
    error_log("Error [$severity]: $message in $file on line $line");
});

// =============================================================================
// INITIALIZATION
// =============================================================================

// Create required directories
if (!file_exists(DATA_DIR)) {
    mkdir(DATA_DIR, 0755, true);

    // Create .htaccess to protect data directory
    $htaccess_content = "Deny from all\n";
    file_put_contents(DATA_DIR . '/.htaccess', $htaccess_content);
}

if (!file_exists(DOWNLOAD_DIR)) {
    mkdir(DOWNLOAD_DIR, 0755, true);
    
    // Create .htaccess to protect download directory
    $htaccess_content = "Deny from all\n";
    file_put_contents(DOWNLOAD_DIR . '/.htaccess', $htaccess_content);
}

// Initialize files.json if it doesn't exist
if (!file_exists(FILES_JSON)) {
    file_put_contents(FILES_JSON, json_encode([]));
}

// Initialize download.log if it doesn't exist
if (!file_exists(DOWNLOAD_LOG)) {
    touch(DOWNLOAD_LOG);
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Sanitize input data to prevent XSS and other attacks
 */
function sanitize_input($data) {
    if (is_array($data)) {
        return array_map('sanitize_input', $data);
    }
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

/**
 * Generate a UUID v4
 */
function generate_uuid() {
    return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand(0, 0xffff), mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0x0fff) | 0x4000,
        mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
    );
}

/**
 * Get client IP address
 */
function get_client_ip() {
    $ip_keys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
    
    foreach ($ip_keys as $key) {
        if (!empty($_SERVER[$key])) {
            $ip = $_SERVER[$key];
            // Handle comma-separated list of IPs
            if (strpos($ip, ',') !== false) {
                $ip = trim(explode(',', $ip)[0]);
            }
            // Validate IP
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

/**
 * Check if IP is rate limited for downloads
 */
function is_rate_limited($ip) {
    if (!file_exists(DOWNLOAD_LOG)) {
        return false;
    }
    
    $log_content = file_get_contents(DOWNLOAD_LOG);
    $lines = array_filter(explode("\n", $log_content));
    $current_time = time();
    
    foreach (array_reverse($lines) as $line) {
        $parts = explode('|', $line);
        if (count($parts) >= 2) {
            $log_ip = $parts[0];
            $timestamp = intval($parts[1]);
            
            if ($log_ip === $ip && ($current_time - $timestamp) < DOWNLOAD_RATE_LIMIT_SECONDS) {
                return true;
            }
        }
    }
    
    return false;
}

/**
 * Log download attempt
 */
function log_download($ip) {
    $log_entry = $ip . '|' . time() . "\n";
    file_put_contents(DOWNLOAD_LOG, $log_entry, FILE_APPEND | LOCK_EX);
}

/**
 * Load files data from JSON
 */
function load_files_data() {
    $json_content = file_get_contents(FILES_JSON);
    return json_decode($json_content, true) ?: [];
}

/**
 * Save files data to JSON
 */
function save_files_data($data) {
    return file_put_contents(FILES_JSON, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
}

/**
 * Validate file extension
 */
function is_allowed_file_type($filename) {
    $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    return in_array($extension, ALLOWED_EXTENSIONS);
}

/**
 * Display error message and exit
 */
function display_error($message) {
    error_log("User error: " . $message);
    echo render_page("Error", "<div class='bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4'>$message</div>");
    exit;
}

/**
 * Display success message and exit
 */
function display_success($message) {
    echo render_page("Success", "<div class='bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-4'>$message</div>");
    exit;
}

/**
 * Render HTML page
 */
function render_page($title, $content) {
    $base_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://" . $_SERVER['HTTP_HOST'] . dirname($_SERVER['SCRIPT_NAME']);
    
    return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$title - </title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex items-center justify-center">
    <div class="max-w-md w-full bg-white rounded-lg shadow-md p-6">
        <h1 class="text-2xl font-bold text-center mb-6 text-gray-800"></h1>
        $content
    </div>
</body>
</html>
HTML;
}

// =============================================================================
// MAIN APPLICATION LOGIC
// =============================================================================

// Sanitize all input
$_GET = sanitize_input($_GET);
$_POST = sanitize_input($_POST);

// Route handling
if (isset($_GET['download'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
        handle_download($_GET['download'], $_POST['password']);
    } else {
        show_download_form($_GET['download']);
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    handle_upload();
} else {
    show_upload_form();
}

// =============================================================================
// ROUTE HANDLERS
// =============================================================================

/**
 * Handle file upload
 */
function handle_upload() {
    try {
        // Validate CSRF (basic check for POST request)
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            throw new Exception('Invalid request method');
        }
        
        // Check if file was uploaded
        if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
            throw new Exception('No file uploaded or upload error occurred');
        }
        
        $file = $_FILES['file'];
        $password = $_POST['password'] ?? '';
        
        // Validate password
        if (strlen($password) < PASSWORD_MIN_LENGTH) {
            throw new Exception('Password must be at least ' . PASSWORD_MIN_LENGTH . ' characters long');
        }
        
        // Validate file size
        if ($file['size'] > MAX_FILE_SIZE) {
            throw new Exception('File size exceeds maximum allowed size of ' . (MAX_FILE_SIZE / 1024 / 1024) . 'MB');
        }
        
        // Validate file type
        if (!is_allowed_file_type($file['name'])) {
            throw new Exception('File type not allowed. Allowed types: ' . implode(', ', ALLOWED_EXTENSIONS));
        }
        
        // Generate UUID and hash password
        $uuid = generate_uuid();
        $password_hash = password_hash($password, PASSWORD_DEFAULT);
        
        // Save file with UUID name
        $file_path = DOWNLOAD_DIR . '/' . $uuid;
        if (!move_uploaded_file($file['tmp_name'], $file_path)) {
            throw new Exception('Failed to save uploaded file');
        }
        
        // Add to files database
        $files_data = load_files_data();
        $files_data[$uuid] = [
            'uuid' => $uuid,
            'original_filename' => $file['name'],
            'download_password_hash' => $password_hash,
            'upload_timestamp' => time()
        ];
        
        if (!save_files_data($files_data)) {
            // Clean up uploaded file if database save fails
            unlink($file_path);
            throw new Exception('Failed to save file metadata');
        }
        
        // Generate links
        $base_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://" . $_SERVER['HTTP_HOST'] . $_SERVER['SCRIPT_NAME'];
        $download_link = $base_url . '?download=' . urlencode($uuid);
        
        $success_message = "
            <p class='mb-4'>File uploaded successfully!</p>
            <div class='space-y-4'>
                <div>
                    <label class='block text-sm font-medium text-gray-700 mb-1'>Download Link:</label>
                    <input type='text' value='$download_link' class='w-full px-3 py-2 border border-gray-300 rounded-md text-sm' readonly onclick='this.select()'>
                </div>
                <div class='text-xs text-gray-600'>
                    <p><strong>Important:</strong> Share this link with the recipient. They will need the password you set to download.</p>
                    <p>The file will be automatically deleted after download.</p>
                    <p>Downloads are limited to 1 per minute per IP address.</p>
                </div>
                <a href='?' class='inline-block bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded'>Upload Another File</a>
            </div>
        ";
        
        display_success($success_message);
        
    } catch (Exception $e) {
        display_error($e->getMessage());
    }
}

/**
 * Show download form
 */
function show_download_form($uuid) {
    // Validate UUID format
    if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $uuid)) {
        display_error('Invalid file ID');
        return;
    }
    
    // Load files data to check if file exists
    $files_data = load_files_data();
    if (!isset($files_data[$uuid])) {
        display_error('File not found or has been deleted');
        return;
    }
    
    $file_info = $files_data[$uuid];
    $original_filename = htmlspecialchars($file_info['original_filename']);
    
    $form = "
        <div class='text-center mb-6'>
            <h2 class='text-lg font-semibold text-gray-800 mb-2'>Download File</h2>
            <p class='text-gray-600 mb-4'>File: <strong>$original_filename</strong></p>
        </div>
        
        <form method='post' class='space-y-4'>
            <div>
                <label for='password' class='block text-sm font-medium text-gray-700 mb-2'>Enter Download Password:</label>
                <input type='password' id='password' name='password' required minlength='" . PASSWORD_MIN_LENGTH . "' class='w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500' autofocus>
                <p class='text-xs text-gray-600 mt-1'>Enter the password provided by the file sender.</p>
            </div>
            
            <button type='submit' class='w-full bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:ring-2 focus:ring-green-500'>Download File</button>
        </form>
        
        <div class='mt-6 text-xs text-gray-600 space-y-2'>
            <p><strong>Note:</strong> The file will be automatically deleted after download.</p>
            <p>Downloads are rate-limited to 1 per minute per IP address.</p>
        </div>
    ";
    
    echo render_page("Download File", $form);
}

/**
 * Handle file download
 */
function handle_download($uuid, $token) {
    try {
        // Validate UUID format
        if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $uuid)) {
            throw new Exception('Invalid file ID');
        }
        
        // Check rate limiting
        $client_ip = get_client_ip();
        if (is_rate_limited($client_ip)) {
            throw new Exception('Rate limit exceeded. Please wait before downloading another file.');
        }
        
        // Load files data
        $files_data = load_files_data();
        
        // Check if file exists in database
        if (!isset($files_data[$uuid])) {
            throw new Exception('File not found or has been deleted');
        }
        
        $file_info = $files_data[$uuid];
        
        // Verify password
        if (!password_verify($token, $file_info['download_password_hash'])) {
            throw new Exception('Invalid download password');
        }
        
        $file_path = DOWNLOAD_DIR . '/' . $uuid;
        
        // Check if physical file exists
        if (!file_exists($file_path)) {
            // Remove orphaned database entry
            unset($files_data[$uuid]);
            save_files_data($files_data);
            throw new Exception('File not found or has been deleted');
        }
        
        // Log the download
        log_download($client_ip);
        
        // Serve the file
        $original_filename = $file_info['original_filename'];
        $file_size = filesize($file_path);
        
        // Set headers for file download
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $original_filename . '"');
        header('Content-Length: ' . $file_size);
        header('Cache-Control: no-cache, must-revalidate');
        header('Pragma: no-cache');
        
        // Output file contents
        readfile($file_path);
        
        // Delete file after successful download
        unlink($file_path);
        unset($files_data[$uuid]);
        save_files_data($files_data);
        
        exit;
        
    } catch (Exception $e) {
        display_error($e->getMessage());
    }
}

/**
 * Show upload form
 */
function show_upload_form() {
    $max_size_mb = MAX_FILE_SIZE / 1024 / 1024;
    $allowed_types = implode(', ', ALLOWED_EXTENSIONS);
    
    $form = "
        <form method='post' enctype='multipart/form-data' class='space-y-4'>
            <div>
                <label for='file' class='block text-sm font-medium text-gray-700 mb-2'>Select File:</label>
                <input type='file' id='file' name='file' required class='w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500'>
                <p class='text-xs text-gray-600 mt-1'>Maximum size: {$max_size_mb}MB. Allowed types: $allowed_types</p>
            </div>
            
            <div>
                <label for='password' class='block text-sm font-medium text-gray-700 mb-2'>Download Password:</label>
                <input type='password' id='password' name='password' required minlength='" . PASSWORD_MIN_LENGTH . "' class='w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500'>
                <p class='text-xs text-gray-600 mt-1'>Minimum " . PASSWORD_MIN_LENGTH . " characters. This password will be required to download the file.</p>
            </div>
            
            <button type='submit' class='w-full bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:ring-2 focus:ring-blue-500'>Upload File</button>
        </form>
        
        <div class='mt-6 text-xs text-gray-600 space-y-2'>
            <p><strong>How it works:</strong></p>
            <ul class='list-disc list-inside space-y-1'>
                <li>Upload a file and set a download password</li>
                <li>Share the download link with the intended recipient</li>
                <li>Recipient enters the password to download the file</li>
                <li>File is automatically deleted after download</li>
                <li>Downloads are rate-limited to 1 per minute per IP</li>
            </ul>
        </div>
    ";
    
    echo render_page("Upload File", $form);
}

?>
