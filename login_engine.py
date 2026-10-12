import re
import time
import requests
from bs4 import BeautifulSoup
from typing import Optional, Dict
from urllib.parse import urljoin, urlparse
import logging
from playwright.sync_api import sync_playwright

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LoginEngine:
    def __init__(self, config: Dict):
        self.config = config
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': config.get('login', {}).get('user_agent', 
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        })
        self.timeout = config.get('login', {}).get('timeout_seconds', 30)
        self.max_retries = config.get('login', {}).get('max_retries', 3)

    def login(self, login_url: str, username: str, password: str) -> Optional[Dict]:
        logger.info(f"Attempting login to: {login_url}")
        result = self._login_http(login_url, username, password)
        if result:
            return result
        return self._login_browser(login_url, username, password)

    def _login_http(self, login_url: str, username: str, password: str) -> Optional[Dict]:
        try:
            response = self.session.get(login_url, timeout=self.timeout, allow_redirects=True)
            if response.status_code != 200:
                return None
            
            csrf_token = self._extract_csrf_token(response.text)
            
            login_data = {
                'username': username,
                'password': password
            }
            
            if csrf_token:
                login_data['csrf_token'] = csrf_token
                login_data['csrfmiddlewaretoken'] = csrf_token
                self.session.headers['X-CSRF-Token'] = csrf_token
            
            form_action = self._extract_form_action(response.text, login_url)
            
            login_response = self.session.post(
                form_action,
                data=login_data,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            if self._verify_login_success(login_response):
                return {
                    'cookies': self.session.cookies.get_dict(),
                    'headers': dict(self.session.headers),
                    'response_text': login_response.text[:1000],
                    'status_code': login_response.status_code,
                    'final_url': login_response.url
                }
            return None
            
        except Exception as e:
            logger.error(f"HTTP login error: {e}")
            return None

    def _login_browser(self, login_url: str, username: str, password: str) -> Optional[Dict]:
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()
                
                page.goto(login_url, timeout=self.timeout * 1000)
                
                try:
                    page.fill('input[name="username"], input[name="email"]', username)
                    page.fill('input[name="password"]', password)
                    page.click('button[type="submit"], input[type="submit"]')
                    page.wait_for_load_state('networkidle', timeout=10000)
                except:
                    pass
                
                cookies = {cookie['name']: cookie['value'] for cookie in context.cookies()}
                browser.close()
                
                return {
                    'cookies': cookies,
                    'headers': {'User-Agent': 'VAPT-Bot/1.0'},
                    'response_text': '',
                    'status_code': 200,
                    'final_url': page.url
                }
        except Exception as e:
            logger.error(f"Browser login error: {e}")
            return None

    def _extract_csrf_token(self, html: str) -> Optional[str]:
        soup = BeautifulSoup(html, 'lxml')
        
        meta_token = soup.select_one('meta[name="csrf-token"]')
        if meta_token and meta_token.get('content'):
            return meta_token['content']
        
        csrf_patterns = ['csrf_token', 'csrf', 'authenticity_token', '_token', 'csrfmiddlewaretoken']
        for pattern in csrf_patterns:
            for input_tag in soup.find_all('input', attrs={'name': re.compile(pattern, re.I)}):
                value = input_tag.get('value')
                if value:
                    return value
        
        js_patterns = [
            r'csrf_token\s*=\s*["\']([^"\']+)["\']',
            r'csrfToken\s*:\s*["\']([^"\']+)["\']'
        ]
        for pattern in js_patterns:
            match = re.search(pattern, html, re.I)
            if match:
                return match.group(1)
        
        return None

    def _extract_form_action(self, html: str, base_url: str) -> str:
        soup = BeautifulSoup(html, 'lxml')
        form = soup.find('form')
        
        if form and form.get('action'):
            action = form['action']
            if action.startswith('/'):
                parsed_base = urlparse(base_url)
                action = f"{parsed_base.scheme}://{parsed_base.netloc}{action}"
            elif not action.startswith('http'):
                action = urljoin(base_url, action)
            return action
        
        return base_url

    def _verify_login_success(self, response) -> bool:
        success_indicators = ['dashboard', 'home', 'welcome', 'account', 'profile', 'logout']
        
        if response.history:
            for resp in response.history:
                if any(indicator in resp.url.lower() for indicator in success_indicators):
                    return True
        
        if any(indicator in response.url.lower() for indicator in success_indicators):
            return True
        
        failure_indicators = ['invalid', 'incorrect', 'failed', 'error', 'wrong', 'try again']
        response_text = response.text.lower()
        if any(indicator in response_text for indicator in failure_indicators):
            return False
        
        if response.cookies:
            session_patterns = ['session', 'auth', 'token', 'sid']
            if any(pattern in cookie_name.lower() for cookie_name in response.cookies.keys() for pattern in session_patterns):
                return True
        
        if 'login' in response.url.lower():
            return False
        
        return response.status_code in [200, 302]