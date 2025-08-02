# SMTP Self-Testing Tool for Ethical Security Testing

## ⚠️ IMPORTANT LEGAL NOTICE

**This tool is designed EXCLUSIVELY for testing your own SMTP servers and systems.**

- **ONLY use this on systems you own or have explicit written permission to test**
- **Unauthorized access to computer systems is illegal in most jurisdictions**
- **Users are solely responsible for compliance with applicable laws**
- **The authors assume no liability for misuse of this tool**

## Purpose

This tool helps security professionals and system administrators:
- Test the security of their own SMTP servers
- Audit password policies on their own systems
- Verify that their SMTP servers properly handle authentication attempts
- Conduct authorized penetration testing with proper documentation

## Safety Features

The tool includes multiple safety measures to prevent misuse:

1. **Explicit Ethical Use Acknowledgment**: Requires user to acknowledge ethical use before running
2. **Domain Whitelist**: Only tests domains you explicitly authorize in the configuration
3. **Rate Limiting**: Prevents aggressive testing that could be detected as abuse
4. **Comprehensive Logging**: All activities are logged with timestamps for audit purposes
5. **Email Notifications**: Sends notifications to your email for any successful authentications
6. **Input Validation**: Validates all target domains against your authorized list

## Installation

1. Ensure you have Python 3.6+ installed
2. No additional dependencies required (uses only standard library)
3. Download the `smtp_self_tester.py` file

## Configuration

Before using the tool, you **MUST** configure it properly:

1. **Edit the CONFIG section** in `smtp_self_tester.py`:
   ```python
   CONFIG = {
       "notification_smtp": {
           "server": "your-smtp-server.com",
           "port": 587,
           "username": "your-email@domain.com",
           "password": "your-password",
           "recipient": "notifications@yourdomain.com"
       },
       
       # CRITICAL: Only add domains you own!
       "authorized_domains": [
           "yourdomain.com",
           "yourotherdomain.org"
       ],
       
       # Adjust rate limiting as needed
       "rate_limit": {
           "max_attempts_per_minute": 10,
           "delay_between_attempts": 2
       }
   }
   ```

2. **Add only domains you own** to the `authorized_domains` list
3. **Configure SMTP notifications** to receive alerts when credentials are found

## Usage

### Step 1: Prepare Input Files

Create these three files in the same directory as the script:

#### `hosts.txt`
List of SMTP server hostnames or IP addresses to test:
```
mail.yourdomain.com
smtp.yourdomain.com
192.168.1.100
```

#### `usernames.txt`
List of usernames to test (without @domain):
```
admin
test
user
postmaster
```

#### `passwords.txt`
List of passwords to test:
```
password
123456
admin
%user%123
%User%@2023
```

**Special Password Variables:**
- `%user%` - Replaced with the username in lowercase
- `%User%` - Replaced with the username in title case

### Step 2: Run the Tool

```bash
python3 smtp_self_tester.py
```

The tool will:
1. Prompt you to acknowledge ethical use
2. Validate your configuration
3. Show which domains are authorized for testing
4. Ask for final confirmation before proceeding
5. Begin testing with rate limiting and logging

### Step 3: Review Results

Results are saved in the `logs/` directory:
- `smtp_test_YYYYMMDD_HHMMSS.log` - Detailed log of all activities
- `valid_credentials_YYYYMMDD_HHMMSS.json` - JSON file with found credentials
- Email notifications sent to your configured address

## Output Example

```
SMTP Self-Testing Tool for Ethical Security Testing
==================================================

============================================================
ETHICAL USE ACKNOWLEDGMENT REQUIRED
============================================================
This tool is designed for testing ONLY your own SMTP servers.
By proceeding, you acknowledge that:
1. You own or have explicit permission to test all target systems
2. You will comply with all applicable laws and regulations
3. You understand that unauthorized access is illegal
4. You accept full responsibility for any consequences
============================================================

Type 'I ACKNOWLEDGE' to proceed (case sensitive): I ACKNOWLEDGE

Authorized domains: yourdomain.com, yourotherdomain.org
Only hosts ending with these domains will be tested.

Proceed with testing? (y/N): y

[2024-01-15 14:30:15] SMTP Self-Testing Tool Started
[2024-01-15 14:30:15] User acknowledged ethical use agreement
[2024-01-15 14:30:15] Starting test with 2 hosts, 3 usernames, 5 passwords
Progress: 1/30 - Testing mail.yourdomain.com
[2024-01-15 14:30:17] Testing mail.yourdomain.com with user admin
[2024-01-15 14:30:19] SUCCESS: mail.yourdomain.com - admin@yourdomain.com:admin123
[2024-01-15 14:30:19] Notification sent for successful login: mail.yourdomain.com
...
```

## Security Best Practices

1. **Only test your own systems** - Never test systems you don't own
2. **Document your testing** - Keep records of authorized testing activities
3. **Use strong passwords** - If weak passwords are found, change them immediately
4. **Monitor logs** - Review all testing logs for any unexpected results
5. **Secure the tool** - Don't leave credentials in configuration files on shared systems
6. **Follow responsible disclosure** - If testing third-party systems with permission, follow responsible disclosure practices

## Troubleshooting

### Common Issues

1. **"UNAUTHORIZED TARGET" messages**:
   - The target host doesn't match any domain in your `authorized_domains` list
   - Add the domain to the authorized list in CONFIG

2. **Connection timeouts**:
   - Target SMTP server may be down or blocking connections
   - Check firewall settings and server status

3. **"Rate limit reached"**:
   - Too many attempts in a short time
   - Adjust rate limiting settings in CONFIG

4. **Email notifications not working**:
   - Check SMTP notification settings in CONFIG
   - Verify your SMTP credentials are correct

### Configuration Validation

The tool will refuse to run if:
- No authorized domains are configured
- Required input files are missing
- User doesn't acknowledge ethical use

## Legal Compliance

Before using this tool:

1. **Obtain proper authorization** for any testing
2. **Document your authorization** in writing
3. **Follow local laws** regarding computer security testing
4. **Respect system owners** and cease testing if requested
5. **Report findings responsibly** to system owners

## Responsible Use Guidelines

- **Start with minimal testing** to verify the tool works correctly
- **Use appropriate rate limiting** to avoid service disruption
- **Test during appropriate hours** to minimize business impact
- **Have contact information** for system owners readily available
- **Stop testing immediately** if you detect any unintended impact

## Support

This tool is provided as-is for educational and authorized testing purposes only. Users are responsible for ensuring their use complies with all applicable laws and regulations.

For questions about ethical security testing practices, consult with:
- Your organization's security team
- Legal counsel familiar with cybersecurity law
- Professional security organizations (SANS, ISC2, etc.)

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**