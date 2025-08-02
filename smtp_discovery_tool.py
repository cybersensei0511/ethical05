#!/usr/bin/env python3
"""
SMTP Server Discovery Tool
=========================

This tool discovers live SMTP servers and reports findings via email.
Designed for legitimate network discovery and security assessment.

IMPORTANT: Only use this tool on networks you own or have explicit permission to scan.
"""

import socket
import sys
import base64
import threading
import queue
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time
import logging
import json
import os
from datetime import datetime
import argparse

# --- SMTP CONFIGURATION ---
CONFIG = {
    "notification_smtp": {
        "server": "mail.museums.or.ke",
        "port": 587,
        "username": "okioko@museums.or.ke", 
        "password": "onesmus@2022",
        "recipient": "skkho87.sm@gmail.com"
    },
    "scanning": {
        "timeout": 10,
        "max_threads": 20,
        "delay_between_scans": 0.1,  # Delay to be respectful
        "retry_failed": False
    },
    "reporting": {
        "email_on_discovery": True,
        "batch_notifications": True,  # Send batch emails instead of individual
        "batch_size": 10,
        "save_results": True
    }
}

# Setup logging
def setup_logging():
    """Configure logging with timestamps and file output"""
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"smtp_discovery_{timestamp}.log")
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

class SMTPServerInfo:
    """Class to store SMTP server information"""
    def __init__(self, host, port=25):
        self.host = host
        self.port = port
        self.is_live = False
        self.banner = ""
        self.supports_auth = False
        self.supports_tls = False
        self.server_software = ""
        self.response_time = 0
        self.timestamp = datetime.now().isoformat()
        self.capabilities = []

class SMTPDiscoveryScanner:
    """Main SMTP discovery scanner class"""
    
    def __init__(self, config):
        self.config = config
        self.discovered_servers = []
        self.processed_hosts = set()
        self.scan_stats = {
            "total_scanned": 0,
            "live_servers": 0,
            "auth_enabled": 0,
            "tls_enabled": 0,
            "start_time": datetime.now()
        }
        
    def check_smtp_server(self, host, port=25, timeout=10):
        """Comprehensive SMTP server check"""
        server_info = SMTPServerInfo(host, port)
        
        try:
            start_time = time.time()
            
            # Initial connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Read banner
            banner = sock.recv(1024).decode(errors='ignore').strip()
            server_info.banner = banner
            server_info.response_time = time.time() - start_time
            
            if not banner.startswith('220'):
                sock.close()
                return server_info
                
            server_info.is_live = True
            
            # Extract server software from banner
            if len(banner.split()) > 1:
                server_info.server_software = ' '.join(banner.split()[1:])
            
            # Send EHLO to get capabilities
            sock.send(b'EHLO discovery.test\r\n')
            ehlo_response = sock.recv(2048).decode(errors='ignore')
            
            if ehlo_response.startswith('250'):
                # Parse capabilities
                for line in ehlo_response.split('\n'):
                    line = line.strip()
                    if line.startswith('250-') or line.startswith('250 '):
                        capability = line[4:].strip()
                        server_info.capabilities.append(capability)
                        
                        # Check for specific capabilities
                        if 'AUTH' in capability.upper():
                            server_info.supports_auth = True
                        if 'STARTTLS' in capability.upper():
                            server_info.supports_tls = True
            
            # Clean disconnect
            sock.send(b'QUIT\r\n')
            sock.recv(256)  # Read QUIT response
            sock.close()
            
            logger.info(f"Live SMTP server found: {host}:{port} - {server_info.server_software}")
            
        except socket.timeout:
            logger.debug(f"Timeout connecting to {host}:{port}")
        except ConnectionRefusedError:
            logger.debug(f"Connection refused: {host}:{port}")
        except Exception as e:
            logger.debug(f"Error scanning {host}:{port}: {e}")
            
        return server_info
    
    def send_notification_email(self, subject, body, is_batch=False):
        """Send email notification about discoveries"""
        try:
            msg = MIMEMultipart()
            msg['Subject'] = subject
            msg['From'] = self.config["notification_smtp"]["username"]
            msg['To'] = self.config["notification_smtp"]["recipient"]
            msg.attach(MIMEText(body, 'plain'))

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
            
            logger.info(f"Email notification sent: {subject}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")
            return False
    
    def format_server_report(self, server_info):
        """Format server information for reporting"""
        report = f"""
SMTP Server Discovery Report
============================

Host: {server_info.host}:{server_info.port}
Status: {'LIVE' if server_info.is_live else 'DOWN'}
Response Time: {server_info.response_time:.2f}s
Timestamp: {server_info.timestamp}

Banner: {server_info.banner}
Server Software: {server_info.server_software}

Capabilities:
- Authentication: {'YES' if server_info.supports_auth else 'NO'}
- TLS Support: {'YES' if server_info.supports_tls else 'NO'}

All Capabilities:
{chr(10).join(f"  - {cap}" for cap in server_info.capabilities)}

Security Notes:
- Open relay testing recommended
- Authentication configuration review suggested
- TLS configuration validation recommended
"""
        return report
    
    def send_individual_notification(self, server_info):
        """Send notification for individual server discovery"""
        if not self.config["reporting"]["email_on_discovery"]:
            return
            
        subject = f"SMTP Server Discovered: {server_info.host}"
        body = self.format_server_report(server_info)
        self.send_notification_email(subject, body)
    
    def send_batch_notification(self, servers):
        """Send batch notification for multiple servers"""
        if not servers:
            return
            
        subject = f"SMTP Discovery Report: {len(servers)} servers found"
        
        body = f"""
SMTP Discovery Batch Report
===========================

Scan Summary:
- Total servers discovered: {len(servers)}
- Authentication enabled: {sum(1 for s in servers if s.supports_auth)}
- TLS enabled: {sum(1 for s in servers if s.supports_tls)}
- Scan timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Discovered Servers:
"""
        
        for i, server in enumerate(servers, 1):
            body += f"""
{i}. {server.host}:{server.port}
   Software: {server.server_software}
   Auth: {'Yes' if server.supports_auth else 'No'} | TLS: {'Yes' if server.supports_tls else 'No'}
   Response: {server.response_time:.2f}s
"""
        
        body += f"""

Detailed Reports:
================
"""
        
        for server in servers:
            body += self.format_server_report(server)
            body += "\n" + "="*50 + "\n"
        
        self.send_notification_email(subject, body, is_batch=True)
    
    def save_results_to_file(self, servers):
        """Save discovery results to JSON file"""
        if not self.config["reporting"]["save_results"]:
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"logs/smtp_discovery_results_{timestamp}.json"
        
        # Convert server objects to dictionaries
        results = {
            "scan_info": {
                "timestamp": timestamp,
                "total_discovered": len(servers),
                "scan_stats": self.scan_stats
            },
            "servers": []
        }
        
        for server in servers:
            server_dict = {
                "host": server.host,
                "port": server.port,
                "is_live": server.is_live,
                "banner": server.banner,
                "server_software": server.server_software,
                "supports_auth": server.supports_auth,
                "supports_tls": server.supports_tls,
                "response_time": server.response_time,
                "timestamp": server.timestamp,
                "capabilities": server.capabilities
            }
            results["servers"].append(server_dict)
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Results saved to {filename}")
        except Exception as e:
            logger.error(f"Failed to save results: {e}")

class SMTPScannerThread(threading.Thread):
    """Worker thread for SMTP scanning"""
    
    def __init__(self, work_queue, scanner, results_queue):
        threading.Thread.__init__(self)
        self.work_queue = work_queue
        self.scanner = scanner
        self.results_queue = results_queue
        self.daemon = True
        
    def run(self):
        while True:
            try:
                host = self.work_queue.get(timeout=1)
                if host is None:  # Shutdown signal
                    break
                    
                # Add small delay to be respectful
                time.sleep(self.scanner.config["scanning"]["delay_between_scans"])
                
                server_info = self.scanner.check_smtp_server(
                    host, 
                    timeout=self.scanner.config["scanning"]["timeout"]
                )
                
                self.scanner.scan_stats["total_scanned"] += 1
                
                if server_info.is_live:
                    self.scanner.scan_stats["live_servers"] += 1
                    if server_info.supports_auth:
                        self.scanner.scan_stats["auth_enabled"] += 1
                    if server_info.supports_tls:
                        self.scanner.scan_stats["tls_enabled"] += 1
                    
                    self.results_queue.put(server_info)
                    self.scanner.discovered_servers.append(server_info)
                    
                    # Send individual notification if not batching
                    if not self.scanner.config["reporting"]["batch_notifications"]:
                        self.scanner.send_individual_notification(server_info)
                
                self.work_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error in scanner thread: {e}")
                self.work_queue.task_done()

def load_target_hosts(filename):
    """Load target hosts from file"""
    hosts = []
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    hosts.append(line)
        logger.info(f"Loaded {len(hosts)} hosts from {filename}")
    except FileNotFoundError:
        logger.error(f"Target file {filename} not found")
    except Exception as e:
        logger.error(f"Error loading hosts: {e}")
    
    return hosts

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="SMTP Server Discovery Tool")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-f", "--file", default="ips.txt", help="Input file with hosts")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--timeout", type=int, default=10, help="Connection timeout")
    parser.add_argument("--no-email", action="store_true", help="Disable email notifications")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.no_email:
        CONFIG["reporting"]["email_on_discovery"] = False
    
    CONFIG["scanning"]["timeout"] = args.timeout
    CONFIG["scanning"]["max_threads"] = args.threads
    
    logger.info("SMTP Server Discovery Tool Starting")
    logger.info("="*50)
    
    # Load target hosts
    hosts = load_target_hosts(args.file)
    if not hosts:
        logger.error("No hosts to scan. Exiting.")
        return
    
    # Initialize scanner
    scanner = SMTPDiscoveryScanner(CONFIG)
    
    # Setup queues
    work_queue = queue.Queue()
    results_queue = queue.Queue()
    
    # Add hosts to work queue
    for host in hosts:
        work_queue.put(host)
    
    # Start worker threads
    threads = []
    for i in range(min(args.threads, len(hosts))):
        thread = SMTPScannerThread(work_queue, scanner, results_queue)
        thread.start()
        threads.append(thread)
    
    logger.info(f"Started {len(threads)} scanner threads")
    logger.info(f"Scanning {len(hosts)} hosts...")
    
    # Monitor progress
    batch_servers = []
    try:
        while True:
            try:
                # Check if scanning is complete
                if work_queue.empty() and all(not t.is_alive() for t in threads):
                    break
                
                # Process results
                try:
                    server_info = results_queue.get(timeout=1)
                    
                    if CONFIG["reporting"]["batch_notifications"]:
                        batch_servers.append(server_info)
                        
                        # Send batch notification when batch size reached
                        if len(batch_servers) >= CONFIG["reporting"]["batch_size"]:
                            scanner.send_batch_notification(batch_servers)
                            batch_servers = []
                    
                except queue.Empty:
                    continue
                    
            except KeyboardInterrupt:
                logger.info("Scan interrupted by user")
                break
                
    finally:
        # Send final batch notification
        if batch_servers and CONFIG["reporting"]["batch_notifications"]:
            scanner.send_batch_notification(batch_servers)
        
        # Stop threads
        for _ in threads:
            work_queue.put(None)  # Shutdown signal
        
        for thread in threads:
            thread.join(timeout=1)
    
    # Final reporting
    scanner.scan_stats["end_time"] = datetime.now()
    duration = scanner.scan_stats["end_time"] - scanner.scan_stats["start_time"]
    
    logger.info("="*50)
    logger.info("SCAN COMPLETE")
    logger.info(f"Duration: {duration}")
    logger.info(f"Total scanned: {scanner.scan_stats['total_scanned']}")
    logger.info(f"Live servers: {scanner.scan_stats['live_servers']}")
    logger.info(f"Auth enabled: {scanner.scan_stats['auth_enabled']}")
    logger.info(f"TLS enabled: {scanner.scan_stats['tls_enabled']}")
    
    # Save results
    if scanner.discovered_servers:
        scanner.save_results_to_file(scanner.discovered_servers)
        
        # Send final summary
        if CONFIG["reporting"]["email_on_discovery"]:
            subject = f"SMTP Discovery Complete: {scanner.scan_stats['live_servers']} servers found"
            body = f"""
SMTP Discovery Summary
=====================

Scan completed successfully!

Statistics:
- Total hosts scanned: {scanner.scan_stats['total_scanned']}
- Live SMTP servers: {scanner.scan_stats['live_servers']}
- Servers with AUTH: {scanner.scan_stats['auth_enabled']}
- Servers with TLS: {scanner.scan_stats['tls_enabled']}
- Scan duration: {duration}

Check the detailed logs and JSON results for complete information.
            """
            scanner.send_notification_email(subject, body)

if __name__ == "__main__":
    main()