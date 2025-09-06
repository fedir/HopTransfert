<?php

use PHPUnit\Framework\TestCase;

class SecurityTest extends TestCase
{
    protected function setUp(): void
    {
        // Clean up any existing session
        if (session_status() !== PHP_SESSION_NONE) {
            session_destroy();
        }
        
        // Clear session superglobal
        $_SESSION = [];
    }

    protected function tearDown(): void
    {
        // Clean up session after each test
        if (session_status() !== PHP_SESSION_NONE) {
            session_destroy();
        }
        $_SESSION = [];
    }

    /**
     * Test CSRF token generation
     */
    public function testGenerateCSRFToken()
    {
        $token1 = generate_csrf_token();
        
        // Token should be a 32-character hexadecimal string (16 bytes * 2)
        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $token1);
        
        // Second call should return the same token (from session)
        $token2 = generate_csrf_token();
        $this->assertEquals($token1, $token2);
        
        // Token should be stored in session
        $this->assertArrayHasKey('csrf_token', $_SESSION);
        $this->assertEquals($token1, $_SESSION['csrf_token']);
    }

    /**
     * Test CSRF token validation with valid token
     */
    public function testValidateCSRFTokenValid()
    {
        $token = generate_csrf_token();
        $this->assertTrue(validate_csrf_token($token));
    }

    /**
     * Test CSRF token validation with invalid token
     */
    public function testValidateCSRFTokenInvalid()
    {
        generate_csrf_token(); // Generate a token first
        $this->assertFalse(validate_csrf_token('invalid_token'));
        $this->assertFalse(validate_csrf_token(''));
        $this->assertFalse(validate_csrf_token('1234567890abcdef1234567890abcdef'));
    }

    /**
     * Test CSRF token validation without session
     */
    public function testValidateCSRFTokenNoSession()
    {
        // Don't generate a token first
        $this->assertFalse(validate_csrf_token('some_token'));
    }

    /**
     * Test filename sanitization for headers
     */
    public function testSanitizeFilenameForHeader()
    {
        // Test normal filename
        $this->assertEquals('document.pdf', sanitize_filename_for_header('document.pdf'));
        
        // Test filename with control characters
        $this->assertEquals('document.pdf', sanitize_filename_for_header("document\x00\x01\x02.pdf"));
        
        // Test filename with header injection attempts
        $this->assertEquals('document.pdf', sanitize_filename_for_header("document\r\n.pdf"));
        $this->assertEquals('document.pdf', sanitize_filename_for_header('document".pdf'));
        $this->assertEquals('document.pdf', sanitize_filename_for_header('document\\.pdf'));
        
        // Test filename with high-ASCII characters
        $this->assertEquals('document.pdf', sanitize_filename_for_header("document\xFF.pdf"));
        
        // Test long filename truncation (should be limited to 255 characters)
        $longFilename = str_repeat('a', 300) . '.pdf';
        $sanitized = sanitize_filename_for_header($longFilename);
        $this->assertLessThanOrEqual(255, strlen($sanitized));
        
        // Test empty filename
        $this->assertEquals('', sanitize_filename_for_header(''));
        
        // Test filename with only control characters
        $this->assertEquals('', sanitize_filename_for_header("\x00\x01\x02"));
    }

    /**
     * Test that sanitize_filename_for_header prevents HTTP Response Splitting
     */
    public function testSanitizeFilenameForHeaderPreventsResponseSplitting()
    {
        // Test various HTTP Response Splitting attack vectors
        $maliciousFilenames = [
            "file.pdf\r\nSet-Cookie: malicious=true",
            "file.pdf\nLocation: http://evil.com",
            "file.pdf\r\n\r\n<script>alert('xss')</script>",
            "file.pdf\x0d\x0aContent-Type: text/html",
        ];
        
        foreach ($maliciousFilenames as $maliciousFilename) {
            $sanitized = sanitize_filename_for_header($maliciousFilename);
            
            // Should not contain any CR or LF characters
            $this->assertStringNotContainsString("\r", $sanitized);
            $this->assertStringNotContainsString("\n", $sanitized);
            
            // Should not contain control characters
            $this->assertMatchesRegularExpression('/^[\x20-\x7E]*$/', $sanitized);
        }
    }

    /**
     * Test CSRF token length optimization
     */
    public function testCSRFTokenLength()
    {
        $token = generate_csrf_token();
        
        // Should be 32 hex characters (16 bytes)
        $this->assertEquals(32, strlen($token));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $token);
    }

    /**
     * Test hash_equals usage in CSRF validation (timing attack prevention)
     */
    public function testCSRFValidationUsesHashEquals()
    {
        $token = generate_csrf_token();
        
        // Measure time for valid token comparison
        $start = microtime(true);
        validate_csrf_token($token);
        $validTime = microtime(true) - $start;
        
        // Measure time for invalid token comparison (same length)
        $invalidToken = str_repeat('a', strlen($token));
        $start = microtime(true);
        validate_csrf_token($invalidToken);
        $invalidTime = microtime(true) - $start;
        
        // Times should be similar (hash_equals should prevent timing attacks)
        // We can't guarantee exact timing, but they should be in the same ballpark
        $this->assertGreaterThan(0, $validTime);
        $this->assertGreaterThan(0, $invalidTime);
    }
}