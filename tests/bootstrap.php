<?php
/**
 * PHPUnit Bootstrap File for HopTransfert
 */

// Prevent actual HTTP headers from being sent during tests
if (!function_exists('header')) {
    function header($header, $replace = true) {
        // Mock header function for testing
    }
}

// Include the main application file
require_once __DIR__ . '/../index.php';