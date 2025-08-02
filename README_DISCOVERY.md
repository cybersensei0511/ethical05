# SMTP Server Discovery Tool

## 🎯 Purpose

This tool is designed to **discover live SMTP servers** and **report findings via email**. It focuses on legitimate network discovery and security assessment rather than credential testing.

## ✨ Key Improvements Over Original

- **Focus on Discovery**: Emphasizes finding live SMTP services
- **Professional Reporting**: Detailed email reports with server capabilities
- **Respectful Scanning**: Built-in delays and proper connection handling
- **Structured Output**: JSON export for further analysis
- **Better Error Handling**: Comprehensive logging and exception management
- **Command Line Interface**: Modern argument parsing with help system

## 🚀 Quick Start

### 1. Configure Your Email Settings
```python
# Edit CONFIG in smtp_discovery_tool.py
CONFIG = {
    "notification_smtp": {
        "server": "mail.museums.or.ke",
        "port": 587,
        "username": "okioko@museums.or.ke",
        "password": "onesmus@2022",
        "recipient": "skkho87.sm@gmail.com"
    }
}
```

### 2. Create Target List
```bash
# Create ips.txt with your target hosts
echo "mail.yourdomain.com" > ips.txt
echo "smtp.yourdomain.com" >> ips.txt
echo "192.168.1.100" >> ips.txt
```

### 3. Run Discovery
```bash
# Basic scan
python3 smtp_discovery_tool.py -t 10 -f ips.txt

# Verbose mode
python3 smtp_discovery_tool.py -t 10 -f ips.txt -v

# Test without emails
python3 smtp_discovery_tool.py -t 10 -f ips.txt --no-email
```

## 📧 What You'll Receive

### Live Server Notifications
When the tool finds a live SMTP server, you'll receive detailed email reports including:

- **Server Information**: Host, port, response time
- **Banner Analysis**: Server software identification
- **Capability Detection**: AUTH, TLS, and other SMTP features
- **Security Recommendations**: Suggested follow-up actions

### Batch Reports
For efficiency, the tool can group discoveries into batch reports:
- Summary statistics
- Server comparison table
- Detailed individual reports
- JSON data for automation

## 📊 Example Email Report

```
Subject: SMTP Server Discovered: mail.example.com

SMTP Server Discovery Report
============================

Host: mail.example.com:25
Status: LIVE
Response Time: 0.34s
Timestamp: 2024-01-15T14:30:15

Banner: 220 mail.example.com ESMTP Postfix
Server Software: Postfix

Capabilities:
- Authentication: YES (PLAIN, LOGIN)
- TLS Support: YES
- Size Limit: 10MB
- Additional: PIPELINING, DSN, 8BITMIME

Security Notes:
- Open relay testing recommended
- Authentication configuration review suggested
- TLS configuration validation recommended
```

## 🛠 Configuration Options

### Scanning Behavior
```python
"scanning": {
    "timeout": 10,              # Connection timeout (seconds)
    "max_threads": 20,          # Concurrent scan threads
    "delay_between_scans": 0.1, # Respectful delay (seconds)
    "retry_failed": False       # Retry failed connections
}
```

### Email Reporting
```python
"reporting": {
    "email_on_discovery": True,    # Send notifications
    "batch_notifications": True,   # Group vs individual emails
    "batch_size": 10,             # Servers per batch
    "save_results": True          # Save JSON files
}
```

## 📁 Output Files

The tool creates structured output in the `logs/` directory:

- **`smtp_discovery_YYYYMMDD_HHMMSS.log`** - Detailed scan log
- **`smtp_discovery_results_YYYYMMDD_HHMMSS.json`** - Machine-readable results

## 🔧 Command Line Options

```bash
python3 smtp_discovery_tool.py [OPTIONS]

Options:
  -t, --threads INTEGER    Number of scanning threads (default: 10)
  -f, --file TEXT         Input file with target hosts (default: ips.txt)  
  -v, --verbose           Enable verbose output
  --timeout INTEGER       Connection timeout in seconds (default: 10)
  --no-email             Disable email notifications
  -h, --help             Show help message
```

## 🎯 Use Cases

### Network Discovery
- Identify all SMTP services in your network
- Map email infrastructure
- Detect unexpected mail servers

### Security Assessment
- Audit SMTP server configurations
- Check TLS deployment consistency
- Validate authentication requirements

### Monitoring & Alerting
- Regular scans to detect changes
- Alert on new SMTP services
- Track server capability changes

## 🔒 Ethical Use Guidelines

### ✅ Appropriate Use
- Scanning your own network infrastructure
- Authorized penetration testing
- Security assessment with permission
- Network inventory and documentation

### ❌ Inappropriate Use
- Scanning networks without permission
- Attempting to access unauthorized systems
- Mass scanning of internet hosts
- Any activity violating terms of service

## 🛡 Safety Features

- **Respectful Scanning**: Built-in delays prevent server overload
- **Error Handling**: Graceful handling of connection issues
- **Logging**: Complete audit trail of all activities
- **Rate Limiting**: Configurable delays between scans
- **Clean Disconnections**: Proper SMTP session termination

## 🔍 Technical Details

### SMTP Capability Detection
The tool identifies:
- Authentication mechanisms (PLAIN, LOGIN, CRAM-MD5, etc.)
- TLS/STARTTLS support
- Message size limits
- Extension support (PIPELINING, DSN, 8BITMIME)
- Server software identification

### Connection Handling
- Proper SMTP protocol implementation
- Clean session establishment and termination
- Timeout handling for unresponsive servers
- Error recovery and logging

## 📈 Performance Considerations

### Recommended Settings
- **Small networks (1-50 hosts)**: 5-10 threads
- **Medium networks (50-500 hosts)**: 10-20 threads  
- **Large networks (500+ hosts)**: 20+ threads with careful monitoring

### Resource Usage
- Memory: ~1-2MB per thread
- Network: Minimal bandwidth usage
- CPU: Low usage with proper delays

## 🔧 Troubleshooting

### Common Issues

**No emails received:**
- Verify SMTP configuration in CONFIG
- Check spam/junk folders
- Test with `--no-email` first

**Connection timeouts:**
- Increase `--timeout` value
- Check network connectivity
- Verify firewall rules

**High resource usage:**
- Reduce thread count
- Increase scan delays
- Monitor system performance

## 📝 Example Target Lists

### Internal Network
```
# Internal mail servers
192.168.1.25
192.168.1.26
10.0.0.25
mail.internal.company.com
```

### Production Environment
```
# Production mail infrastructure
mail.company.com
smtp.company.com
mx1.company.com
mx2.company.com
```

## 🚀 Advanced Usage

### Automated Scanning
```bash
# Daily scan with cron
0 2 * * * cd /path/to/scanner && python3 smtp_discovery_tool.py -t 10 -f daily_targets.txt
```

### Integration with Other Tools
- Export JSON for further analysis
- Feed results into vulnerability scanners
- Integrate with network monitoring systems

---

## 📞 Support

This tool is designed for legitimate security testing and network discovery. Always ensure you have proper authorization before scanning any network infrastructure.

**Remember: Responsible disclosure and ethical use are essential for maintaining trust in the security community.**