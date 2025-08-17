# HopTransfert 🚀

**A minimalist, secure, and anonymous file sharing solution**

HopTransfert is a single-file PHP application that enables secure, password-protected file sharing without requiring user registration or complex setup. Perfect for quick, secure file transfers with automatic cleanup.

[![PHP Version](https://img.shields.io/badge/PHP-8.1%2B-blue.svg)](https://php.net)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-OWASP%20Top%2010-red.svg)](https://owasp.org/www-project-top-ten/)

<img width="576" height="384" alt="image" src="https://github.com/user-attachments/assets/95de7bde-928b-4918-94b6-c3e52f3d628e" />

## ✨ Features

- **🔐 Password Protected**: Files are secured with user-defined passwords
- **👤 Anonymous**: No user registration or login required
- **🗑️ Auto-Cleanup**: Files automatically deleted after download
- **🛡️ Secure**: OWASP Top 10 compliant with comprehensive security measures
- **⚡ Rate Limited**: Built-in protection against abuse (1 download/minute per IP)
- **📁 Single File**: Entire application in one PHP file
- **💾 No Database**: Uses JSON for metadata storage
- **🎨 Clean UI**: Responsive design with Tailwind CSS
- **📱 Mobile Friendly**: Works perfectly on all devices

## 🚀 Quick Start

### Requirements

- PHP 8.1 or higher
- Web server (Apache, Nginx, etc.)
- Write permissions for the application directory

### Installation

1. **Download the application:**
   ```bash
   wget https://raw.githubusercontent.com/yourusername/HopTransfert/main/index.php
   ```

2. **Upload to your web server:**
   ```bash
   # Upload index.php to your web root directory
   cp index.php /var/www/html/
   ```

3. **Set proper permissions:**
   ```bash
   chmod 755 /var/www/html/index.php
   chmod 755 /var/www/html/  # Ensure directory is writable
   ```

4. **Access your application:**
   ```
   https://yourdomain.com/index.php
   ```

That's it! The application will automatically create the required directories and files on first run.

## 🏗️ Directory Structure

After first run, HopTransfert creates the following structure:

```
your-web-root/
├── index.php              # Main application file
├── data/                  # Application data directory
│   ├── files.json         # File metadata database
│   ├── download.log       # Download tracking for rate limiting
│   └── php_errors.log     # Error logs
└── download/              # File storage directory
    ├── .htaccess          # Access protection
    └── [uuid-files]       # Uploaded files (UUID named)
```

## 📖 How It Works

### 1. Upload Process
1. User selects a file and sets a download password
2. File is uploaded and stored with a unique UUID filename
3. Password is securely hashed using PHP's `password_hash()`
4. User receives a clean download link (no password in URL)

### 2. Download Process
1. Recipient clicks the download link
2. Password form is displayed showing the original filename
3. Recipient enters the password via secure POST form
4. If password is correct, file downloads immediately
5. File and metadata are automatically deleted after successful download

### 3. Security Features
- **Rate Limiting**: 1 download per minute per IP address
- **Secure File Storage**: Files stored outside web root with UUID names
- **Password Protection**: Secure hashing with verification
- **Input Sanitization**: All inputs sanitized against XSS
- **Access Control**: Download directory protected by .htaccess

## ⚙️ Configuration

All configuration is done via constants at the top of `index.php`:

```php
// Rate limiting
const DOWNLOAD_RATE_LIMIT_SECONDS = 60;

// File upload limits
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB

// Allowed file extensions
const ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'txt', 'doc', 'docx', 'zip', 'rar'];

// Security
const PASSWORD_MIN_LENGTH = 6;

...
```

### Customization Options

| Setting | Default | Description |
|---------|---------|-------------|
| `DOWNLOAD_RATE_LIMIT_SECONDS` | 60 | Seconds between downloads per IP |
| `MAX_FILE_SIZE` | 50MB | Maximum file upload size |
| `ALLOWED_EXTENSIONS` | Various | Whitelist of allowed file types |
| `HASH_SALT` | 'your-secret-salt-here' | Hash salt used for data anonymization |
| `PASSWORD_MIN_LENGTH` | 6 | Minimum password length |
| `MAX_LOG_LINES` | 5 | Prevent log bloat |


## 🔒 Security Features

HopTransfert implements multiple layers of security:

### OWASP Top 10 Compliance
- **A01 Broken Access Control**: Files protected by UUID and .htaccess
- **A02 Cryptographic Failures**: Secure password hashing with `password_hash()`
- **A03 Injection**: All inputs sanitized with `htmlspecialchars()`
- **A04 Insecure Design**: Rate limiting and secure file handling
- **A05 Security Misconfiguration**: Proper error logging, no debug info exposure
- **A06 Vulnerable Components**: Self-contained, minimal dependencies
- **A07 Authentication Failures**: Secure password verification
- **A08 Software Integrity**: Single-file application
- **A09 Logging Failures**: Comprehensive error and access logging
- **A10 Server-Side Request Forgery**: No external requests made

### Additional Security Measures
- **UUID File Names**: Prevents path traversal and filename conflicts
- **POST-based Authentication**: Passwords never exposed in URLs
- **Automatic Cleanup**: Reduces attack surface by removing files
- **File Type Validation**: Whitelist-based file extension checking
- **Error Handling**: Secure error logging without information disclosure

### GDPR Compliance
- Download log: Using hash (with a secret salt) instead of storing full IPs

### Ressource control
- Download log: Keeping log size bounded (truncating old lines)

## 🌟 Use Cases

### Personal Use
- Share documents with friends or colleagues
- Send files that are too large for email
- Temporary file sharing without cloud storage

### Business Applications
- Secure client file delivery
- Internal document sharing
- Temporary project file distribution
- Contractor file exchanges

### Development & Testing
- Share build artifacts
- Distribute test files
- Quick file transfers between environments

## 🔧 Advanced Configuration

### Web Server Configuration

#### Apache (.htaccess)
The application automatically creates `.htaccess` files, but you can enhance security:

```apache
# Additional security headers
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options DENY
    Header always set X-XSS-Protection "1; mode=block"
</IfModule>

# Disable server signature
ServerTokens Prod
ServerSignature Off
```

#### Nginx
```nginx
server {
    listen 443 ssl;
    server_name yourdomain.com;
    
    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    
    # Deny access to data directory
    location /data/ {
        deny all;
    }
    
    # Deny access to download directory
    location /download/ {
        deny all;
    }
    
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }
}
```

### SSL/HTTPS Setup
For production use, always enable HTTPS:

```bash
# Using Certbot for Let's Encrypt
certbot --nginx -d yourdomain.com
```

### File Size Limits
Adjust PHP settings for larger files:

```ini
; php.ini
upload_max_filesize = 100M
post_max_size = 100M
max_execution_time = 300
memory_limit = 256M
```

## 📊 Monitoring & Maintenance

### Log Files
HopTransfert generates several log files for monitoring:

```bash
# View error logs
tail -f data/php_errors.log

# View download activity
tail -f data/download.log

# Check web server logs
tail -f /var/log/apache2/access.log
```

### Maintenance Tasks
```bash
# Clean up old log files (optional)
find data/ -name "*.log" -mtime +30 -delete

# Monitor disk usage
du -sh data/ download/

# Check for orphaned files (shouldn't exist with auto-cleanup)
find download/ -type f -mtime +1
```

## 🐛 Troubleshooting

### Common Issues

#### File Upload Fails
```bash
# Check permissions
ls -la /var/www/html/
chmod 755 /var/www/html/

# Check PHP configuration
php -i | grep upload_max_filesize
php -i | grep post_max_size
```

#### Downloads Not Working
```bash
# Verify .htaccess is working
curl -I https://yourdomain.com/download/test-file

# Check error logs
tail data/php_errors.log
```

#### Rate Limiting Too Strict
Edit `index.php` and adjust:
```php
const DOWNLOAD_RATE_LIMIT_SECONDS = 30; // Reduce to 30 seconds
```

### Debug Mode
For development, you can enable debug mode by modifying the error display settings:

```php
// Temporarily enable for debugging (DO NOT use in production)
ini_set('display_errors', 1);
error_reporting(E_ALL);
```

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

### Development Setup
```bash
git clone https://github.com/yourusername/HopTransfert.git
cd HopTransfert
# Set up your local web server to point to the directory
```

### Code Style
- Follow PSR-12 coding standards
- Use meaningful variable names
- Add comments for complex logic
- Maintain security-first approach

### Pull Request Process
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Security Reports
Please report security vulnerabilities privately by emailing [security@yourdomain.com](mailto:security@yourdomain.com).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with security best practices from [OWASP](https://owasp.org/)
- UI powered by [Tailwind CSS](https://tailwindcss.com/)
- Inspired by the need for simple, secure file sharing
- Accelerated development with [Claude.AI](https://claude.ai/)

## 📞 Support

- **Documentation**: Check this README and code comments
- **Issues**: [GitHub Issues](https://github.com/yourusername/HopTransfert/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/HopTransfert/discussions)

## 🔮 Roadmap

- [ ] Multi-file upload support
- [ ] Download expiration times
- [ ] Admin panel for monitoring
- [ ] Docker containerization
- [ ] API endpoints
- [ ] File preview capabilities

---

**Made with ❤️ for secure, simple file sharing**

*HopTransfert - Because file sharing should be simple and secure.*
