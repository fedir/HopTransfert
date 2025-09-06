<?php
/**
 * Simple security test script to verify our optimizations
 */

// Mock header function to prevent actual headers being sent
function header($header, $replace = true) {
    echo "HEADER: $header\n";
}

// Include main application
include_once 'index.php';

echo "=== Security Optimization Tests ===\n\n";

// Test 1: CSRF Token Generation
echo "Test 1: CSRF Token Generation\n";
$token1 = generate_csrf_token();
echo "Generated token: $token1\n";
echo "Token length: " . strlen($token1) . " characters\n";
echo "Expected: 32 characters (16 bytes hex)\n";
echo "Valid format: " . (preg_match('/^[0-9a-f]{32}$/', $token1) ? "YES" : "NO") . "\n";

// Test same token returned on subsequent calls
$token2 = generate_csrf_token();
echo "Same token on second call: " . ($token1 === $token2 ? "YES" : "NO") . "\n\n";

// Test 2: CSRF Token Validation
echo "Test 2: CSRF Token Validation\n";
echo "Valid token validates: " . (validate_csrf_token($token1) ? "YES" : "NO") . "\n";
echo "Invalid token rejects: " . (!validate_csrf_token('invalid_token') ? "YES" : "NO") . "\n";
echo "Empty token rejects: " . (!validate_csrf_token('') ? "YES" : "NO") . "\n\n";

// Test 3: Filename Sanitization
echo "Test 3: Filename Sanitization\n";

$testCases = [
    'document.pdf' => 'document.pdf',
    "doc\x00ument.pdf" => 'document.pdf',
    "doc\r\nument.pdf" => 'document.pdf', 
    'doc"ument.pdf' => 'document.pdf',
    'doc\\ument.pdf' => 'document.pdf',
    "doc\xFFument.pdf" => 'document.pdf',
    str_repeat('a', 300) . '.pdf' => 'truncated'
];

foreach ($testCases as $input => $expected) {
    $result = sanitize_filename_for_header($input);
    $status = ($expected === 'truncated') ? (strlen($result) <= 255 ? "PASS" : "FAIL") : ($result === $expected ? "PASS" : "FAIL");
    echo "Input: " . addcslashes($input, "\x00..\x1F") . "\n";
    echo "Output: $result\n";
    echo "Status: $status\n\n";
}

echo "=== Session Configuration Test ===\n";
echo "Session status before: " . session_status() . "\n";

// Generate token to trigger session start
generate_csrf_token();

echo "Session status after: " . session_status() . "\n";
echo "Session started: " . (session_status() === PHP_SESSION_ACTIVE ? "YES" : "NO") . "\n";

echo "\n=== All Tests Complete ===\n";
?>