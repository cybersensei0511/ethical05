#!/usr/bin/env python3
"""
Example Configuration for SMTP Self-Testing Tool
================================================

Copy the CONFIG section below and paste it into smtp_self_tester.py
replacing the existing CONFIG dictionary.

IMPORTANT: Only add domains that you own or have explicit permission to test!
"""

# Example configuration - CUSTOMIZE THIS FOR YOUR ENVIRONMENT
CONFIG = {
    "notification_smtp": {
        # Your SMTP server for sending notifications
        "server": "mail.yourdomain.com",
        "port": 587,  # or 25, 465, 2525 depending on your server
        "username": "notifications@yourdomain.com",
        "password": "your-secure-password-here",
        "recipient": "security-team@yourdomain.com"
    },
    
    # CRITICAL SAFETY MEASURE: Only domains you own should be listed here
    # The tool will REFUSE to test any host that doesn't end with these domains
    "authorized_domains": [
        "yourdomain.com",           # Your primary domain
        "subdomain.yourdomain.com", # Subdomains are okay
        "yourcompany.org",          # Additional domains you own
        # "testlab.internal",       # Internal test domains
        # "dev.yourdomain.com",     # Development environments
        
        # DO NOT INCLUDE:
        # - Domains you don't own
        # - Third-party domains (even with permission)
        # - Generic domains like gmail.com, yahoo.com, etc.
    ],
    
    # Rate limiting settings to prevent abuse
    "rate_limit": {
        "max_attempts_per_minute": 10,  # Reduce this for gentler testing
        "delay_between_attempts": 2     # Seconds between each attempt
    },
    
    # Testing parameters
    "connection_timeout": 15,    # Connection timeout in seconds
    "max_threads": 5,           # Number of concurrent tests (be conservative)
    "verbose": True             # Show progress during testing
}

# Example input files content:

EXAMPLE_HOSTS_TXT = """
# List your SMTP servers here (one per line)
# Only servers from domains in authorized_domains will be tested

mail.yourdomain.com
smtp.yourdomain.com
mx1.yourdomain.com
192.168.1.100
10.0.0.50
"""

EXAMPLE_USERNAMES_TXT = """
# Usernames to test (without @domain - domain is auto-detected)
# Common administrative accounts to test:

admin
administrator
postmaster
root
test
user
support
info
contact
webmaster
"""

EXAMPLE_PASSWORDS_TXT = """
# Passwords to test
# Use %user% for username substitution, %User% for title case

# Common weak passwords
password
123456
admin
root
test

# Username-based passwords
%user%
%user%123
%user%2023
%user%@123
%User%123

# Company-specific patterns (customize for your org)
CompanyName123
Welcome123
Password123
company@2023
"""

if __name__ == "__main__":
    print("This is an example configuration file.")
    print("Copy the CONFIG dictionary into smtp_self_tester.py")
    print("and customize it for your environment.")
    print("\nRemember:")
    print("1. Only add domains you own to authorized_domains")
    print("2. Use strong authentication for notification_smtp")
    print("3. Test conservatively with appropriate rate limits")
    print("4. Always get proper authorization before testing")