import re
import time
import requests
from bs4 import BeautifulSoup
from typing import Optional, Dict, Tuple
from urllib.parse import urljoin, urlparse
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LoginEngine:
    """Robust login engine with proper success/failure detection"""
    
    # Common username field names
    USERNAME_FIELDS = [
        'username', 'user', 'email', 'userid', 'user_id', 'login',
        'uname', 'login_id', 'loginid', 'account', 'usr', 'mail',
        'email_address', 'user_name', 'employee_id', 'staff_id'
    ]
    
    # Common password field names
    PASSWORD_FIELDS = [
        'password', 'passwd', 'pass', 'pwd', 'pass_word', 'user_password',
        'userpassword', 'passwrd', 'secret'
    ]
    
    # Common CSRF token field names
    CSRF_FIELDS = [
        'csrf_token', 'csrf', 'csrfmiddlewaretoken', '_token', 'authenticity_token',
        'token', 'csrf_token_name', '__RequestVerificationToken', '_csrf',
        'xsrf_token', 'x-csrf-token', 'csrf-token'
    ]
    
    # Success indicators in URL
    SUCCESS_URL_INDICATORS = [
        'dashboard', 'home', 'welcome', 'account', 'profile', 'myaccount',
        'mypage', 'settings', 'admin', 'portal', 'main', 'index', 'app',
        'inbox', 'feed', 'overview', 'summary', 'user', 'member'
    ]
    
    # Failure indicators in response body
    FAILURE_BODY_INDICATORS = [
        'invalid credentials', 'invalid username or password',
        'invalid password', 'invalid username', 'incorrect password',
        'incorrect username', 'incorrect credentials',
        'wrong password', 'wrong username', 'wrong credentials',
        'login failed', 'login unsuccessful', 'authentication failed',
        'authentication error', 'access denied', 'unauthorized',
        'bad credentials', 'please try again', 'try again',
        'username or password is incorrect', 'username does not exist',
        'user does not exist', 'no such user', 'account not found',
        'please check your credentials', 'login error', 'sign in failed',
        'signin failed', 'sign-in failed'
    ]
    
    # Success indicators in response body  
    SUCCESS_BODY_INDICATORS = [
        'logout', 'log out', 'sign out', 'signout', 'log-out',
        'my account', 'my profile', 'welcome back', 'dashboard'
    ]

    def __init__(self, config: Dict):
        self.config = config
        self.login_config = config.get('login', {})
        self.timeout = self.login_config.get('timeout_seconds', 30)
        self.verify_ssl = False
        
        # User agent
        self.user_agent = self.login_config.get(
            'user_agent',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        )

    # ============================================================
    # MAIN LOGIN METHOD
    # ============================================================
    def login(self, login_url: str, username: str, password: str) -> Optional[Dict]:
        """
        Attempt to log in to the target application.
        
        Returns:
            Dict with session info if successful, None otherwise
        """
        logger.info(f"🔐 Attempting login to: {login_url}")
        logger.info(f"   Username: {username}")
        
        # Create fresh session
        session = requests.Session()
        session.verify = self.verify_ssl
        session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        try:
            # ============================================
            # STEP 1: Fetch the login page
            # ============================================
            logger.info(f"📄 Step 1: Fetching login page...")
            response = session.get(login_url, timeout=self.timeout, allow_redirects=True)
            
            if response.status_code != 200:
                logger.error(f"❌ Failed to fetch login page (HTTP {response.status_code})")
                return None
            
            login_page_html = response.text
            login_page_url = response.url  # After any redirects
            
            logger.info(f"✅ Login page fetched ({len(login_page_html)} bytes)")
            
            # ============================================
            # STEP 2: Parse the login form
            # ============================================
            logger.info(f"🔍 Step 2: Analyzing login form...")
            
            form_info = self._find_login_form(login_page_html, login_page_url)
            if not form_info:
                logger.error("❌ Could not find a login form on the page")
                return None
            
            action_url = form_info['action']
            method = form_info['method']
            username_field = form_info['username_field']
            password_field = form_info['password_field']
            csrf_token = form_info['csrf_token']
            csrf_field_name = form_info['csrf_field_name']
            hidden_fields = form_info['hidden_fields']
            
            logger.info(f"✅ Form found:")
            logger.info(f"   Action:   {action_url}")
            logger.info(f"   Method:   {method}")
            logger.info(f"   Username field: {username_field}")
            logger.info(f"   Password field: {password_field}")
            if csrf_token:
                logger.info(f"   CSRF token found: {csrf_field_name}")
            
            # ============================================
            # STEP 3: Build the login payload
            # ============================================
            payload = {}
            
            # Add hidden fields (except CSRF which we'll handle separately)
            for hname, hvalue in hidden_fields.items():
                payload[hname] = hvalue
            
            # Add CSRF token if found
            if csrf_token and csrf_field_name:
                payload[csrf_field_name] = csrf_token
            
            # Add username and password
            payload[username_field] = username
            payload[password_field] = password
            
            # Add common extras some apps expect
            payload.setdefault('submit', 'Login')
            payload.setdefault('login', '1')
            
            logger.info(f"📤 Step 3: Sending login request...")
            logger.debug(f"   Payload fields: {list(payload.keys())}")
            
            # ============================================
            # STEP 4: Send the login request
            # ============================================
            headers = {
                'Referer': login_page_url,
                'Origin': f"{urlparse(login_page_url).scheme}://{urlparse(login_page_url).netloc}",
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            # Add CSRF token to header too (some apps need it)
            if csrf_token:
                headers['X-CSRF-Token'] = csrf_token
                headers['X-CSRFToken'] = csrf_token
            
            if method == 'POST':
                login_response = session.post(
                    action_url,
                    data=payload,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            else:
                login_response = session.get(
                    action_url,
                    params=payload,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            
            logger.info(f"📥 Response received (HTTP {login_response.status_code})")
            
            # ============================================
            # STEP 5: Verify the login
            # ============================================
            success, reason = self._verify_login(
                session=session,
                login_page_url=login_page_url,
                login_response=login_response,
                original_login_page=login_page_html
            )
            
            if success:
                logger.info(f"✅ LOGIN SUCCESSFUL — Reason: {reason}")
                
                # Check for session cookies
                cookies = session.cookies.get_dict()
                if cookies:
                    logger.info(f"🍪 Session cookies: {list(cookies.keys())}")
                else:
                    logger.warning("⚠️  No cookies were set — session may not persist")
                
                # Extract CSRF token from final page for future requests
                final_csrf = self._extract_csrf_from_html(login_response.text)
                
                return {
                    'success': True,
                    'cookies': cookies,
                    'headers': dict(session.headers),
                    'login_url': login_url,
                    'final_url': login_response.url,
                    'csrf_token': final_csrf or csrf_token or '',
                    'reason': reason,
                    'session': session  # Return the actual session object
                }
            else:
                logger.error(f"❌ LOGIN FAILED — Reason: {reason}")
                return None
                
        except requests.exceptions.Timeout:
            logger.error("❌ Login request timed out")
            return None
        except requests.exceptions.ConnectionError as e:
            logger.error(f"❌ Connection error: {e}")
            return None
        except Exception as e:
            logger.error(f"❌ Login error: {e}")
            return None

    # ============================================================
    # FORM DISCOVERY
    # ============================================================
    def _find_login_form(self, html: str, page_url: str) -> Optional[Dict]:
        """Find the login form and extract all fields"""
        try:
            soup = BeautifulSoup(html, 'lxml')
        except Exception:
            soup = BeautifulSoup(html, 'html.parser')
        
        forms = soup.find_all('form')
        if not forms:
            # Maybe there's no <form> — try to find by input fields
            return self._find_login_inputs_without_form(soup, page_url)
        
        best_form = None
        best_score = -1
        
        for form in forms:
            score, info = self._score_form(form, page_url)
            if score > best_score:
                best_score = score
                best_form = info
        
        # Require a minimum score (must have at least a password field)
        if best_score < 50:
            logger.warning(f"⚠️  Best form score too low ({best_score}) — may not be a login form")
            # Still try to use it if it has a password field
            if best_form and best_form.get('password_field'):
                return best_form
            return None
        
        return best_form

    def _score_form(self, form, page_url: str) -> Tuple[int, Dict]:
        """Score a form on how likely it is to be a login form"""
        score = 0
        
        # Find inputs
        inputs = form.find_all(['input', 'textarea', 'select'])
        
        username_field = None
        password_field = None
        csrf_token = None
        csrf_field_name = None
        hidden_fields = {}
        
        for inp in inputs:
            name = (inp.get('name') or '').lower()
            input_type = (inp.get('type') or 'text').lower()
            value = inp.get('value', '')
            
            if not name:
                continue
            
            # Check for password field
            if input_type == 'password' or any(p in name for p in self.PASSWORD_FIELDS):
                password_field = inp.get('name')
                score += 40  # Password is a strong signal
                continue
            
            # Check for username/email field
            if input_type in ['text', 'email']:
                if any(u in name for u in self.USERNAME_FIELDS):
                    username_field = inp.get('name')
                    score += 30
                    continue
                if input_type == 'email':
                    username_field = inp.get('name')
                    score += 25
                    continue
            
            # Check for CSRF token
            if any(c in name for c in self.CSRF_FIELDS):
                csrf_token = value
                csrf_field_name = inp.get('name')
                score += 5
                continue
            
            # Other hidden fields
            if input_type == 'hidden':
                hidden_fields[inp.get('name')] = value
                continue
        
        # Form method bonus
        method = (form.get('method') or 'GET').upper()
        if method == 'POST':
            score += 10
        
        # Form action analysis
        action = form.get('action', '')
        action_lower = action.lower()
        if any(k in action_lower for k in ['login', 'signin', 'auth', 'session', 'authenticate']):
            score += 15
        
        # ID/class analysis
        form_id = (form.get('id') or '').lower()
        form_class = ' '.join(form.get('class') or []).lower()
        form_attrs = f"{form_id} {form_class}"
        if any(k in form_attrs for k in ['login', 'signin', 'auth']):
            score += 10
        
        # Build the action URL
        if not action:
            action_url = page_url
        else:
            action_url = urljoin(page_url, action)
        
        info = {
            'action': action_url,
            'method': method,
            'username_field': username_field,
            'password_field': password_field,
            'csrf_token': csrf_token,
            'csrf_field_name': csrf_field_name,
            'hidden_fields': hidden_fields,
            'score': score
        }
        
        return score, info

    def _find_login_inputs_without_form(self, soup, page_url: str) -> Optional[Dict]:
        """Fallback: find username/password inputs even if no <form> tag"""
        username_field = None
        password_field = None
        csrf_token = None
        csrf_field_name = None
        hidden_fields = {}
        
        for inp in soup.find_all('input'):
            name = (inp.get('name') or '').lower()
            input_type = (inp.get('type') or 'text').lower()
            value = inp.get('value', '')
            
            if not name:
                continue
            
            if input_type == 'password' or any(p in name for p in self.PASSWORD_FIELDS):
                password_field = inp.get('name')
            elif input_type in ['text', 'email'] and any(u in name for u in self.USERNAME_FIELDS):
                username_field = inp.get('name')
            elif any(c in name for c in self.CSRF_FIELDS):
                csrf_token = value
                csrf_field_name = inp.get('name')
            elif input_type == 'hidden':
                hidden_fields[inp.get('name')] = value
        
        if not password_field:
            return None
        
        return {
            'action': page_url,
            'method': 'POST',
            'username_field': username_field,
            'password_field': password_field,
            'csrf_token': csrf_token,
            'csrf_field_name': csrf_field_name,
            'hidden_fields': hidden_fields,
            'score': 50
        }

    # ============================================================
    # LOGIN VERIFICATION — This is the critical part
    # ============================================================
    def _verify_login(self, session, login_page_url: str, 
                       login_response, original_login_page: str) -> Tuple[bool, str]:
        """
        Verify if login was actually successful.
        
        Returns: (success_bool, reason_string)
        """
        
        response_text_lower = login_response.text.lower()
        final_url = login_response.url.lower()
        login_page_url_lower = login_page_url.lower()
        
        # ---------------------------------------------
        # CHECK 1: Explicit failure messages in body
        # ---------------------------------------------
        for indicator in self.FAILURE_BODY_INDICATORS:
            if indicator in response_text_lower:
                # Make sure it's not just part of a script or CSS
                # Check if it's in visible text
                if self._indicator_in_visible_text(login_response.text, indicator):
                    return False, f"Failure message found: '{indicator}'"
        
        # ---------------------------------------------
        # CHECK 2: Are we still on the login page?
        # ---------------------------------------------
        still_on_login = self._is_still_on_login_page(
            original_login_page, login_response.text
        )
        
        # ---------------------------------------------
        # CHECK 3: URL change (redirect to dashboard/home)
        # ---------------------------------------------
        url_changed = final_url != login_page_url_lower
        
        # Remove common query params for comparison
        clean_final = self._clean_url_for_comparison(final_url)
        clean_login = self._clean_url_for_comparison(login_page_url_lower)
        path_changed = clean_final != clean_login
        
        # ---------------------------------------------
        # CHECK 4: Session cookies present
        # ---------------------------------------------
        cookies = session.cookies.get_dict()
        has_session_cookie = self._has_session_cookie(cookies)
        
        # ---------------------------------------------
        # CHECK 5: Success indicators in body
        # ---------------------------------------------
        has_success_indicator = False
        for indicator in self.SUCCESS_BODY_INDICATORS:
            if self._indicator_in_visible_text(login_response.text, indicator):
                has_success_indicator = True
                break
        
        # ---------------------------------------------
        # CHECK 6: Password field gone?
        # ---------------------------------------------
        password_field_gone = not self._has_password_field(login_response.text)
        
        # ---------------------------------------------
        # DECISION LOGIC
        # ---------------------------------------------
        
        # Explicit failure takes priority
        # (already returned above if failure found)
        
        # Strong success signals
        success_signals = []
        failure_signals = []
        
        if url_changed and path_changed:
            # Check if new URL contains success keywords
            if any(ind in final_url for ind in self.SUCCESS_URL_INDICATORS):
                success_signals.append("Redirected to success URL")
            else:
                # URL changed but no clear success indicator — weak signal
                success_signals.append("URL changed after login")
        
        if has_session_cookie:
            success_signals.append("Session cookie set")
        
        if has_success_indicator:
            success_signals.append("Success indicator in body")
        
        if password_field_gone and not still_on_login:
            success_signals.append("Password field gone from page")
        
        # Failure signals
        if still_on_login:
            failure_signals.append("Still on the same login page")
        
        if not has_session_cookie and not url_changed:
            failure_signals.append("No session cookie and no URL change")
        
        # ---------------------------------------------
        # FINAL DECISION
        # ---------------------------------------------
        
        # If still on login page with no session cookie → definitely failed
        if still_on_login and not has_session_cookie:
            return False, "Still on login page, no session cookie"
        
        # If still on login page even with cookies → likely failed
        if still_on_login:
            return False, "Still on login page after submission"
        
        # If we have strong success signals and no failure signals
        if len(success_signals) >= 2:
            return True, " | ".join(success_signals)
        
        # If we have URL change + session cookie
        if url_changed and has_session_cookie:
            return True, f"URL changed to {final_url} with session cookie"
        
        # If we have a session cookie + password field gone
        if has_session_cookie and password_field_gone:
            return True, "Session cookie + password field gone"
        
        # If URL changed and password field is gone
        if url_changed and password_field_gone:
            return True, "URL changed and password field gone"
        
        # Ambiguous — be conservative and mark as failed
        return False, f"Ambiguous result (signals: {success_signals}, failures: {failure_signals})"

    def _indicator_in_visible_text(self, html: str, indicator: str) -> bool:
        """Check if an indicator appears in visible page text (not in scripts/styles)"""
        try:
            soup = BeautifulSoup(html, 'lxml')
        except Exception:
            soup = BeautifulSoup(html, 'html.parser')
        
        # Remove script and style tags
        for tag in soup(['script', 'style', 'noscript']):
            tag.decompose()
        
        visible_text = soup.get_text(separator=' ', strip=True).lower()
        return indicator in visible_text

    def _is_still_on_login_page(self, original_html: str, response_html: str) -> bool:
        """Check if we're still on the login page"""
        if not original_html or not response_html:
            return False
        
        # Extract just the form signature
        orig_form = self._extract_form_signature(original_html)
        resp_form = self._extract_form_signature(response_html)
        
        # If both have password fields and they match significantly
        if orig_form and resp_form:
            # Check for overlapping field names
            overlap = len(orig_form & resp_form)
            if overlap >= 2:  # At least 2 matching fields (typically username + password)
                return True
        
        # If response still has a password field AND original had one
        if self._has_password_field(response_html):
            # Check for common login-only indicators
            resp_lower = response_html.lower()
            login_keywords = ['sign in', 'log in', 'login', 'signin', 'enter your password']
            matches = sum(1 for kw in login_keywords if kw in resp_lower)
            if matches >= 2:
                return True
        
        return False

    def _extract_form_signature(self, html: str) -> set:
        """Extract the set of form field names"""
        try:
            soup = BeautifulSoup(html, 'lxml')
        except Exception:
            soup = BeautifulSoup(html, 'html.parser')
        
        fields = set()
        for form in soup.find_all('form'):
            for inp in form.find_all(['input', 'textarea']):
                name = inp.get('name', '')
                if name:
                    fields.add(name.lower())
        return fields

    def _has_password_field(self, html: str) -> bool:
        """Check if HTML contains a password input"""
        try:
            soup = BeautifulSoup(html, 'lxml')
        except Exception:
            soup = BeautifulSoup(html, 'html.parser')
        
        for inp in soup.find_all('input', {'type': 'password'}):
            if inp.get('name'):
                return True
        return False

    def _has_session_cookie(self, cookies: Dict[str, str]) -> bool:
        """Check if cookies contain a likely session identifier"""
        if not cookies:
            return False
        
        session_keywords = [
            'session', 'sess', 'sid', 'auth', 'token', 'jwt',
            'user', 'login', 'access', 'refresh', 'access_token',
            'PHPSESSID', 'JSESSIONID', 'ASP.NET_SessionId', 'csrftoken'
        ]
        
        for cookie_name in cookies.keys():
            cookie_lower = cookie_name.lower()
            if any(kw in cookie_lower for kw in session_keywords):
                return True
        
        # Some apps set arbitrary-named session cookies — if there are multiple cookies, that's a good sign
        return len(cookies) >= 2

    def _clean_url_for_comparison(self, url: str) -> str:
        """Remove query string and fragment for URL comparison"""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"

    def _extract_csrf_from_html(self, html: str) -> Optional[str]:
        """Extract CSRF token from HTML"""
        try:
            soup = BeautifulSoup(html, 'lxml')
        except Exception:
            soup = BeautifulSoup(html, 'html.parser')
        
        # Check meta tags first
        for meta in soup.find_all('meta'):
            name = (meta.get('name') or '').lower()
            if 'csrf' in name and meta.get('content'):
                return meta['content']
        
        # Check input fields
        for inp in soup.find_all('input', {'type': 'hidden'}):
            name = (inp.get('name') or '').lower()
            if any(c in name for c in self.CSRF_FIELDS):
                return inp.get('value', '')
        
        return None
