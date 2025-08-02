# Ethical SMTP Live Server Scanner

This tool is designed for **ethical security testing only** to identify live SMTP servers and test authentication with proper authorization.

## Key Improvements

### 1. Live Server Detection
- **Primary Focus**: Detects live SMTP servers responding on port 25
- **Email Notifications**: Sends immediate email alerts for each live server found
- **Separate Logging**: Creates `live_smtp_servers.txt` with all responsive servers

### 2. Enhanced Email Notifications
- **Live Server Alerts**: Notifies when any SMTP server responds
- **Valid Credentials**: Notifies when authentication succeeds
- **Detailed Information**: Includes timestamps, banners, and full details

### 3. Better Error Handling
- **Robust Logging**: Comprehensive logging to file and console
- **Input Validation**: Validates command line arguments and input files
- **Graceful Failures**: Handles missing files and network errors

### 4. Security Improvements
- **Proper Authentication**: Better SMTP authentication handling
- **Connection Management**: Proper socket cleanup and timeouts
- **Rate Limiting**: Thread-based control for responsible scanning

## Usage

### Command Line Arguments
```bash
python smtp_scanner.py <threads> <verbose> <debug>
```

**Parameters:**
- `threads`: Number of concurrent threads (recommended: 5-20)
- `verbose`: Set to 'bad' to log non-responsive servers
- `debug`: Debug level (d1, d2, d3, d4)
  - `d1`: Show authentication attempts
  - `d2`: Show errors and exceptions
  - `d3`: Show both attempts and errors
  - `d4`: Show successful authentications

### Examples
```bash
# Live server detection with moderate verbosity
python smtp_scanner.py 10 bad d1

# Comprehensive scanning with full debug
python smtp_scanner.py 5 bad d3

# Initialize input files
python smtp_scanner.py a
```

## Configuration

### SMTP Settings (Edit in script)
```python
SMTP_SERVER = "your-smtp-server.com"
SMTP_PORT = 587
SMTP_USER = "your-username@domain.com"
SMTP_PASS = "your-password"
NOTIFY_EMAIL = "alerts@yourdomain.com"
```

## Input Files

### Required Files
1. **ips.txt** - Target IP addresses or hostnames (one per line)
2. **users.txt** - Usernames to test (one per line)
3. **pass.txt** - Passwords to test (one per line)
4. **subs.txt** - Domain suffixes for banner parsing

### Special Password Patterns
- `%user%` - Replaced with username in lowercase
- `%User%` - Replaced with username in title case
- Use `|` to separate multiple passwords per line

## Output Files

1. **live_smtp_servers.txt** - All responsive SMTP servers with banners
2. **valid.txt** - Successfully authenticated credentials
3. **bad.txt** - Non-responsive servers (if verbose=bad)
4. **smtp_scanner.log** - Comprehensive logging

## Email Notifications

The scanner sends two types of email notifications:

### 1. Live Server Found
```
Subject: Live SMTP Server Found: [IP/Hostname]
Body: Host, Banner, Timestamp
```

### 2. Valid Credentials Found
```
Subject: Valid SMTP Credentials Found
Body: Host, Username, Password, Banner, Timestamp
```

## Ethical Usage Guidelines

### ✅ Appropriate Use
- Testing your own mail servers
- Authorized penetration testing
- Security assessments with written permission
- Educational purposes in controlled environments

### ❌ Prohibited Use
- Unauthorized access attempts
- Attacking servers without permission
- Brute forcing without authorization
- Any illegal activities

## Legal Disclaimer

This tool is provided for educational and authorized testing purposes only. Users are responsible for:
- Obtaining proper authorization before testing
- Complying with all applicable laws and regulations
- Ensuring ethical use of the software

**Unauthorized use of this tool may violate computer crime laws.**

## Technical Features

### Multi-threading
- Configurable thread count for optimal performance
- Queue-based task distribution
- Graceful thread error handling

### Network Handling
- Configurable timeouts
- Proper socket cleanup
- Connection state management

### Logging and Monitoring
- Structured logging with timestamps
- Progress tracking
- Error reporting and debugging

## Troubleshooting

### Common Issues
1. **Email notifications not working**
   - Check SMTP credentials and server settings
   - Verify network connectivity to notification server
   - Check firewall and security settings

2. **No live servers detected**
   - Verify target IPs are correct and reachable
   - Check if port 25 is filtered by firewalls
   - Ensure network connectivity

3. **High error rates**
   - Reduce thread count to avoid overwhelming targets
   - Increase timeout values for slow networks
   - Check input file formatting

### Performance Tuning
- **Thread Count**: Start with 5-10 threads, adjust based on network capacity
- **Timeouts**: Increase for slow networks, decrease for faster scanning
- **Queue Size**: Adjust maxsize based on available memory

## Support

For issues or questions related to ethical security testing, ensure you have:
1. Proper authorization documentation
2. Clear scope definition
3. Appropriate legal framework

Remember: **Always obtain explicit written permission before testing any systems you do not own.**