import warnings
import urllib3
import ssl
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings globally
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
warnings.filterwarnings('ignore', category=InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def create_secure_session(verify_ssl: bool = False):
    """
    Create a requests session with SSL verification disabled by default
    This is safe for VAPT as we're testing, not production
    """
    session = requests.Session()
    session.verify = verify_ssl
    
    # Set headers to look like a real browser
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    })
    
    return session