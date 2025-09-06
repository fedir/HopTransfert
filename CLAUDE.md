# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HopTransfert is a single-file PHP application for secure, anonymous file sharing with password protection and automatic cleanup. The entire application logic is contained in `index.php`.

## Architecture

### Core Components
- **Single File Application**: All logic is in `index.php` (~600 lines)
- **File Storage**: Files stored in `download/` directory with UUID filenames
- **Metadata Database**: JSON file (`data/files.json`) stores file metadata
- **Rate Limiting**: Simple log-based system using `data/download.log`
- **Security**: OWASP Top 10 compliant with password hashing, input sanitization, and access controls

### Key Functions (index.php)
- `sanitize_input()` - XSS prevention for all user inputs
- `generate_uuid()` - UUID v4 generation for file naming
- `get_client_ip()` / `hash_ip()` - GDPR-compliant IP handling for rate limiting
- `is_rate_limited()` / `log_download()` - Rate limiting system (1 download/minute per IP)
- `handle_upload()` - File upload processing with validation
- `handle_download()` - Password verification and file serving
- `render_page()` - HTML page generation with Tailwind CSS

### Configuration Constants (lines 12-35)
All configuration is done via constants at the top of `index.php`:
- `DOWNLOAD_RATE_LIMIT_SECONDS` - Rate limiting interval (default: 5 seconds)
- `MAX_FILE_SIZE` - Upload size limit (default: 50MB)
- `ALLOWED_EXTENSIONS` - Whitelisted file types
- `PASSWORD_MIN_LENGTH` - Minimum password length (default: 6)
- `HASH_SALT` - Salt for IP hashing (change in production)
- `MAX_LOG_LINES` - Log size control (default: 5)

### Directory Structure
```
/
├── index.php              # Main application
├── data/                  # Application data (protected by .htaccess)
│   ├── files.json         # File metadata database
│   ├── download.log       # Rate limiting log (IP hashes)
│   └── php_errors.log     # Error logging
└── download/              # File storage (protected by .htaccess)
    ├── .htaccess          # "Deny from all"
    └── [uuid-files]       # Uploaded files with UUID names
```

## Development Commands

This is a pure PHP application with no build system, package manager, or test framework:

- **No build process** - Direct PHP execution
- **No linting** - No PHP linting tools configured
- **No tests** - No test framework present
- **No dependencies** - Single-file application with no external dependencies

### Testing the Application
```bash
# Local development server
php -S localhost:8000 index.php

# Check PHP syntax
php -l index.php
```

### Production Deployment
```bash
# Set permissions
chmod 755 index.php
chmod 755 . # Ensure directory is writable for data/ and download/ creation

# Web server setup required (Apache/Nginx with PHP 8.1+)
```

## Security Features

### OWASP Top 10 Compliance
- **Broken Access Control**: UUID file names + .htaccess protection
- **Cryptographic Failures**: `password_hash()` for passwords, `hash()` for IP anonymization  
- **Injection**: `htmlspecialchars()` sanitization for all inputs
- **Rate Limiting**: 1 download/minute per IP with GDPR-compliant hashed logging
- **File Validation**: Extension whitelist and size limits
- **Auto-cleanup**: Files deleted immediately after download

### Key Security Functions
- `sanitize_input()` - Prevents XSS on all user data
- `hash_ip()` - GDPR-compliant IP anonymization using SHA256 + salt
- `is_allowed_file_type()` - Whitelist-based file type validation
- Password verification using `password_verify()` with secure hashing

## File Workflow

1. **Upload**: File → UUID rename → JSON metadata → Download link generation
2. **Download**: Link access → Password form → Verification → File serve → Auto-delete
3. **Cleanup**: Automatic deletion after successful download + orphaned file cleanup

## Configuration Notes

- Change `HASH_SALT` constant for production deployments
- Adjust `DOWNLOAD_RATE_LIMIT_SECONDS` based on usage patterns
- Modify `ALLOWED_EXTENSIONS` array for different file type requirements  
- Update `MAX_FILE_SIZE` based on server capabilities and `php.ini` settings

## Error Handling

- Custom error handler logs to `data/php_errors.log`
- User-facing errors via `display_error()` function
- No sensitive information exposed to users
- Log rotation built-in to prevent bloat (MAX_LOG_LINES)