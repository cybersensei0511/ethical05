# SMTP Discovery Tool Usage Guide

## Overview

This tool focuses on **discovering live SMTP servers** and reporting them to your email. It's designed for legitimate network discovery and security assessment purposes.

## Key Features

✅ **Live SMTP Server Discovery** - Identifies responding SMTP services  
✅ **Server Capability Detection** - Checks for AUTH, TLS, and other features  
✅ **Email Notifications** - Sends detailed reports to your email  
✅ **Batch Reporting** - Groups discoveries into comprehensive reports  
✅ **JSON Export** - Saves structured data for further analysis  
✅ **Respectful Scanning** - Built-in delays to avoid overwhelming servers  

## Quick Start

### 1. Configure Email Settings

Edit the `CONFIG` section in `smtp_discovery_tool.py`:

```python
CONFIG = {
    "notification_smtp": {
        "server": "your-smtp-server.com",
        "port": 587,
        "username": "your-email@domain.com",
        "password": "your-password",
        "recipient": "alerts@yourdomain.com"
    }
}
```

### 2. Prepare Target List

Create `ips.txt` with your target hosts:
```
mail.yourdomain.com
smtp.company.org
192.168.1.100
10.0.0.50
```

### 3. Run the Scanner

```bash
# Basic scan with 10 threads
python3 smtp_discovery_tool.py -t 10 -f ips.txt

# Verbose output
python3 smtp_discovery_tool.py -t 10 -f ips.txt -v

# Disable email notifications (testing mode)
python3 smtp_discovery_tool.py -t 10 -f ips.txt --no-email

# Custom timeout
python3 smtp_discovery_tool.py -t 10 -f ips.txt --timeout 15
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-t, --threads` | Number of scanning threads | 10 |
| `-f, --file` | Input file with target hosts | ips.txt |
| `-v, --verbose` | Enable verbose output | False |
| `--timeout` | Connection timeout in seconds | 10 |
| `--no-email` | Disable email notifications | False |

## Email Report Examples

### Individual Server Discovery
```
Subject: SMTP Server Discovered: mail.example.com

SMTP Server Discovery Report
============================

Host: mail.example.com:25
Status: LIVE
Response Time: 0.34s
Timestamp: 2024-01-15T14:30:15

Banner: 220 mail.example.com ESMTP Postfix
Server Software: mail.example.com ESMTP Postfix

Capabilities:
- Authentication: YES
- TLS Support: YES

All Capabilities:
  - PIPELINING
  - SIZE 10240000
  - VRFY
  - ETRN
  - STARTTLS
  - AUTH PLAIN LOGIN
  - 8BITMIME
  - DSN

Security Notes:
- Open relay testing recommended
- Authentication configuration review suggested
- TLS configuration validation recommended
```

### Batch Report (10 servers)
```
Subject: SMTP Discovery Report: 10 servers found

SMTP Discovery Batch Report
===========================

Scan Summary:
- Total servers discovered: 10
- Authentication enabled: 8
- TLS enabled: 9
- Scan timestamp: 2024-01-15 14:30:15

Discovered Servers:

1. mail.company.com:25
   Software: Postfix
   Auth: Yes | TLS: Yes
   Response: 0.23s

2. smtp.domain.org:25
   Software: Microsoft Exchange
   Auth: Yes | TLS: Yes
   Response: 0.45s

[... detailed reports for each server follow ...]
```

## Output Files

### Log Files (`logs/` directory)
- `smtp_discovery_YYYYMMDD_HHMMSS.log` - Detailed scan log
- `smtp_discovery_results_YYYYMMDD_HHMMSS.json` - Structured results

### Example JSON Output
```json
{
  "scan_info": {
    "timestamp": "20240115_143015",
    "total_discovered": 5,
    "scan_stats": {
      "total_scanned": 100,
      "live_servers": 5,
      "auth_enabled": 4,
      "tls_enabled": 5
    }
  },
  "servers": [
    {
      "host": "mail.example.com",
      "port": 25,
      "is_live": true,
      "banner": "220 mail.example.com ESMTP Postfix",
      "server_software": "mail.example.com ESMTP Postfix",
      "supports_auth": true,
      "supports_tls": true,
      "response_time": 0.234,
      "timestamp": "2024-01-15T14:30:15",
      "capabilities": ["PIPELINING", "SIZE", "STARTTLS", "AUTH PLAIN LOGIN"]
    }
  ]
}
```

## Configuration Options

### Scanning Behavior
```python
"scanning": {
    "timeout": 10,              # Connection timeout
    "max_threads": 20,          # Maximum concurrent threads
    "delay_between_scans": 0.1, # Delay between scans (respectful)
    "retry_failed": False       # Retry failed connections
}
```

### Email Reporting
```python
"reporting": {
    "email_on_discovery": True,    # Send email notifications
    "batch_notifications": True,   # Batch vs individual emails
    "batch_size": 10,             # Servers per batch email
    "save_results": True          # Save JSON results
}
```

## Best Practices

### 🔒 **Security & Ethics**
- Only scan networks you own or have permission to test
- Respect rate limits and server resources
- Document your scanning activities
- Follow responsible disclosure for any findings

### ⚡ **Performance**
- Start with fewer threads (5-10) for initial testing
- Adjust timeout based on network conditions
- Use batch notifications to reduce email volume
- Monitor system resources during large scans

### 📊 **Analysis**
- Review JSON output for systematic analysis
- Cross-reference with network documentation
- Identify unexpected SMTP services
- Check for consistent security configurations

## Troubleshooting

### Common Issues

**No email notifications received:**
- Check SMTP configuration in CONFIG
- Verify email credentials
- Test with `--no-email` flag first

**Connection timeouts:**
- Increase `--timeout` value
- Check network connectivity
- Verify target hosts are reachable

**High resource usage:**
- Reduce thread count (`-t 5`)
- Increase scan delays in CONFIG
- Monitor system performance

**Permission errors:**
- Ensure you have permission to scan targets
- Check firewall rules
- Verify network access

## Sample Target Lists

### Internal Network Discovery
```
# Internal mail servers
192.168.1.25
192.168.1.26
10.0.0.25
10.0.1.25
```

### Domain-based Discovery
```
# Company mail servers
mail.company.com
smtp.company.com
mx1.company.com
mx2.company.com
exchange.company.com
```

### Mixed Environment
```
# Production mail servers
mail.prod.company.com
smtp.prod.company.com

# Development/staging
mail.dev.company.com
mail.staging.company.com

# Internal services  
192.168.10.25
10.0.5.100
```

## Integration Ideas

### Automated Monitoring
- Run periodic scans to detect new SMTP services
- Compare results to baseline configurations
- Alert on unexpected changes

### Security Assessment
- Identify servers with weak configurations
- Check for consistent TLS deployment
- Validate authentication requirements

### Network Inventory
- Maintain up-to-date SMTP service inventory
- Document server capabilities and versions
- Track configuration changes over time

---

**Remember:** This tool is designed for legitimate discovery and assessment. Always ensure you have proper authorization before scanning any network infrastructure.