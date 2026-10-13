import re
import time
import json
import os
from typing import Dict, List, Set, Optional
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode
from collections import deque
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from endpoint_storage import EndpointStorage
from js_analyzer import JSAnalyzer
from form_analyzer import FormAnalyzer
from ollama_analyzer import OllamaVulnerabilityAnalyzer
from exploit_engine import ExploitEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ReconEngine:
    def __init__(self, config: Dict, storage: EndpointStorage, session):
        self.config = config
        self.storage = storage
        self.session = session
        self.recon_config = config.get('recon', {})
        
        self.max_depth = self.recon_config.get('max_depth', 5)
        self.max_pages = self.recon_config.get('max_pages', 1000)
        self.concurrent_requests = self.recon_config.get('concurrent_requests', 10)
        self.ignore_extensions = self.recon_config.get('ignore_extensions', [])
        
        # State
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.queue = deque()
        self.js_files_found: Set[str] = set()
        
        # Target domain (set during discover)
        self.target_domain: str = ""
        self.target_host: str = ""
        
        # Third-party domains to ignore
        self.third_party_domains = [
            # Social Media
            'facebook.com', 'fb.com', 'instagram.com', 'twitter.com', 'x.com',
            'linkedin.com', 'youtube.com', 'youtu.be', 'tiktok.com', 'pinterest.com',
            'reddit.com', 'snapchat.com', 'whatsapp.com', 'telegram.org', 't.me',
            'discord.com', 'discord.gg', 'tumblr.com', 'medium.com', 'quora.com',
            'weibo.com', 'vk.com', 'line.me', 'kakao.com',
            
            # Search / Big Tech
            'google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com',
            'googletagmanager.com', 'google-analytics.com', 'doubleclick.net',
            'bing.com', 'yahoo.com', 'duckduckgo.com', 'baidu.com', 'yandex.com',
            'apple.com', 'icloud.com', 'microsoft.com', 'live.com', 'outlook.com',
            'office.com', 'windows.com', 'msn.com', 'skype.com',
            'amazon.com', 'aws.amazon.com', 'cloudfront.net',
            'adobe.com', 'oracle.com', 'ibm.com', 'salesforce.com',
            
            # CDNs / Static Hosting
            'cloudflare.com', 'cloudflareinsights.com', 'cdnjs.cloudflare.com',
            'jsdelivr.net', 'unpkg.com', 'bootstrapcdn.com', 'fontawesome.com',
            'use.fontawesome.com', 'fonts.googleapis.com', 'fonts.gstatic.com',
            'maxcdn.com', 'stackpathdns.com', 'akamaihd.net', 'akamai.net',
            'fastly.net', 'fastlylb.net', 'netlify.app', 'vercel.app',
            'herokuapp.com', 'github.io', 'gitlab.io', 'surge.sh',
            
            # Analytics / Tracking
            'hotjar.com', 'mixpanel.com', 'segment.com', 'segment.io',
            'amplitude.com', 'fullstory.com', 'logrocket.com', 'sentry.io',
            'newrelic.com', 'datadoghq.com', 'optimizely.com', 'crazyegg.com',
            'clicky.com', 'kissmetrics.com', 'chartbeat.com', 'quantserve.com',
            'scorecardresearch.com', 'comscore.com', 'nielsen.com',
            
            # Advertising
            'adsystem.com', 'adnxs.com', 'criteo.com', 'taboola.com', 'outbrain.com',
            'pubmatic.com', 'rubiconproject.com', 'openx.net', 'casalemedia.com',
            
            # Other common third parties
            'intercom.io', 'intercom.com', 'zendesk.com', 'freshdesk.com',
            'hubspot.com', 'mailchimp.com', 'sendgrid.net', 'sendgrid.com',
            'stripe.com', 'paypal.com', 'razorpay.com', 'paytm.com',
            'twilio.com', 'sendbird.com', 'pusher.com', 'pubnub.com',
            'vimeo.com', 'dailymotion.com', 'wistia.com', 'jwplayer.com',
            'typekit.net', 'typeform.com', 'calendly.com', 'zoom.us',
            'dropbox.com', 'box.com', 'wetransfer.com', 'drive.google.com',
            'gravatar.com', 'wordpress.com', 'wordpress.org', 'wp.com',
            'w.org', 'wix.com', 'squarespace.com', 'shopify.com', 'bigcartel.com',
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly',
            'w3.org', 'schema.org', 'ogp.me', 'creativecommons.org',
            'wikipedia.org', 'wikimedia.org', 'mozilla.org', 'apache.org',
            'nginx.org', 'php.net', 'mysql.com', 'postgresql.org', 'mongodb.com',
            'unpkg.com', 'npmjs.com', 'pypi.org', 'github.com', 'githubusercontent.com',
            'gitlab.com', 'bitbucket.org', 'stackoverflow.com', 'stackexchange.com',
            'ampproject.org', 'cdn.ampproject.org', 'bunnycdn.com', 'bunny.net',
        ]
        
        # Extensions to skip
        self.skip_extensions = [
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.ico',
            '.mp4', '.mp3', '.avi', '.mov', '.wmv', '.flv', '.wav', '.ogg',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.rar', '.7z', '.tar', '.gz', '.exe', '.dmg', '.apk',
            '.woff', '.woff2', '.ttf', '.eot', '.otf',
            '.css', '.map'
        ]
        
        # Endpoints tracking
        self.endpoints_by_type = {
            'html_pages': [],
            'api_endpoints': [],
            'js_files': [],
            'forms': [],
            'json_endpoints': [],
            'xml_endpoints': [],
            'other': []
        }
        
        # Initialize analyzers
        self.js_analyzer = JSAnalyzer(config, storage)
        self.form_analyzer = FormAnalyzer(config, storage)
        
        # Ollama config
        ollama_config = config.get('ollama', {})
        ollama_host = ollama_config.get('host', 'http://localhost:11434')
        ollama_model = ollama_config.get('model', 'llama3.1:8b')
        
        logger.info(f"🔗 Connecting to Ollama at: {ollama_host}")
        
        self.ollama_analyzer = OllamaVulnerabilityAnalyzer(
            model_name=ollama_model,
            config=ollama_config,
            host=ollama_host
        )
        
        self.exploit_engine = None
        self.exploit_results = None
        self.vuln_report = None

    # ============================================================
    # MAIN DISCOVERY METHOD
    # ============================================================
    def discover(self, start_url: str) -> Dict:
        """Full discovery — crawl ALL URLs dynamically from the target domain only"""
        logger.info(f"🚀 Starting dynamic reconnaissance on: {start_url}")
        
        # Extract the target host and domain
        parsed = urlparse(start_url)
        self.target_host = parsed.netloc.lower()
        self.target_domain = self._get_registered_domain(self.target_host)
        
        logger.info(f"🎯 Target Host:   {self.target_host}")
        logger.info(f"🎯 Target Domain: {self.target_domain}")
        logger.info(f"🛡️  All third-party domains will be filtered out")
        
        # Save initial target info
        self._save_endpoint_incremental(start_url, 'html_pages', 'start_url')
        
        # Add start URL to queue
        self.queue.append((start_url, 0, None))  # (url, depth, source)
        self.discovered_urls.add(start_url)
        
        # Process the queue with thread pool
        with ThreadPoolExecutor(max_workers=self.concurrent_requests) as executor:
            futures = []
            
            while self.queue and len(self.visited_urls) < self.max_pages:
                url, depth, source = self.queue.popleft()
                
                if url in self.visited_urls:
                    continue
                
                if self._should_skip(url):
                    continue
                
                future = executor.submit(self._process_url, url, depth, source)
                futures.append(future)
                
                # Keep thread pool balanced
                if len(futures) >= self.concurrent_requests * 2:
                    for f in as_completed(futures[:self.concurrent_requests]):
                        try:
                            f.result()
                        except Exception as e:
                            logger.debug(f"Future error: {e}")
                    futures = futures[self.concurrent_requests:]
            
            # Wait for remaining
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.debug(f"Future error: {e}")
        
        # Save everything
        logger.info(f"💾 Saving discovered endpoints...")
        self._save_all_endpoints()
        self.storage.save()
        
        # Print discovery summary
        self._print_discovery_summary()
        
        # AI vulnerability analysis
        logger.info("🧠 Running AI vulnerability analysis...")
        self.vuln_report = self._analyze_vulnerabilities()
        
        # Automated exploitation
        if self.vuln_report and self.config.get('exploitation', {}).get('enabled', True):
            vulnerabilities = self.vuln_report.get('vulnerabilities', [])
            if vulnerabilities:
                logger.info(f"🔨 Starting automated exploitation of {len(vulnerabilities)} vulnerabilities...")
                self.exploit_engine = ExploitEngine(self.config, self.session, self.storage)
                self.exploit_results = self.exploit_engine.exploit_all(vulnerabilities)
                self.exploit_engine.print_summary()
                self._save_exploitation_results(self.exploit_results)
        
        return {
            'visited': len(self.visited_urls),
            'discovered': len(self.discovered_urls),
            'js_files': self.js_analyzer.stats['total_files'],
            'secrets': self.js_analyzer.stats['secrets_found'],
            'vulnerabilities': len(self.vuln_report.get('vulnerabilities', [])) if self.vuln_report else 0,
            'successful_exploits': len(self.exploit_results.get('successful_exploits', [])) if self.exploit_results else 0
        }

    # ============================================================
    # URL PROCESSING
    # ============================================================
    def _process_url(self, url: str, depth: int, source: Optional[str] = None):
        """Process a single URL and extract all same-domain URLs from it"""
        if url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        logger.info(f"🔍 [{depth}] {url}")
        
        try:
            # Send request
            response = self.session.get(
                url,
                timeout=15,
                allow_redirects=True,
                verify=False
            )
            
            # Store response metadata
            content_type = response.headers.get('content-type', '').lower()
            status_code = response.status_code
            
            # Skip non-successful responses (but log them)
            if status_code >= 400:
                logger.debug(f"Non-200 response: {status_code} - {url}")
                self.storage.add_url(url, 'GET', {
                    'status_code': status_code,
                    'content_type': content_type,
                    'discovered_from': source or 'direct'
                })
                return
            
            # Classify and store
            endpoint_type = self._classify_endpoint(url, content_type)
            self._save_endpoint_incremental(url, endpoint_type, source or 'direct')
            
            self.storage.add_url(url, 'GET', {
                'status_code': status_code,
                'content_type': content_type,
                'content_length': len(response.content),
                'discovered_from': source or 'direct'
            })
            
            # Process based on content type
            if 'json' in content_type:
                self._process_json_response(url, response.text, depth)
            elif 'xml' in content_type:
                self._process_xml_response(url, response.text, depth)
            elif 'javascript' in content_type or url.endswith('.js'):
                self._process_js_file(url, response.text)
            elif 'html' in content_type or 'text' in content_type:
                self._process_html_response(url, response.text, depth)
            else:
                # Unknown type — still try to parse as HTML
                self._process_html_response(url, response.text, depth)
            
        except requests.exceptions.Timeout:
            logger.debug(f"Timeout: {url}")
        except requests.exceptions.ConnectionError:
            logger.debug(f"Connection error: {url}")
        except requests.exceptions.TooManyRedirects:
            logger.debug(f"Too many redirects: {url}")
        except Exception as e:
            logger.debug(f"Error processing {url}: {e}")

    # ============================================================
    # HTML PROCESSING — Extract ALL URLs
    # ============================================================
    def _process_html_response(self, base_url: str, html: str, depth: int):
        """Parse HTML and extract every possible URL"""
        try:
            soup = BeautifulSoup(html, 'lxml')
        except Exception:
            soup = BeautifulSoup(html, 'html.parser')
        
        # 1. Extract all <a href> links
        for tag in soup.find_all('a', href=True):
            href = tag['href']
            self._queue_url(base_url, href, depth, 'a_href')
        
        # 2. Extract all <link href> (stylesheets, preload, etc.)
        for tag in soup.find_all('link', href=True):
            href = tag['href']
            self._queue_url(base_url, href, depth, 'link_href')
        
        # 3. Extract all <script src>
        for tag in soup.find_all('script', src=True):
            src = tag['src']
            full_url = urljoin(base_url, src)
            if self._is_same_domain(full_url):
                if full_url not in self.js_files_found:
                    self.js_files_found.add(full_url)
                    self._queue_url(base_url, src, depth, 'script_src')
        
        # 4. Extract all <form action>
        for form in soup.find_all('form'):
            action = form.get('action', '')
            if action:
                self._queue_url(base_url, action, depth, 'form_action')
            self._process_form(form, base_url)
        
        # 5. Extract all <img src> (for endpoints reference)
        for tag in soup.find_all('img', src=True):
            src = tag['src']
            # Still queue to see if server responds with something interesting
            if not self._is_skippable_extension(src):
                self._queue_url(base_url, src, depth, 'img_src')
        
        # 6. Extract <iframe src>
        for tag in soup.find_all('iframe', src=True):
            src = tag['src']
            self._queue_url(base_url, src, depth, 'iframe_src')
        
        # 7. Extract <source src>
        for tag in soup.find_all('source', src=True):
            src = tag['src']
            self._queue_url(base_url, src, depth, 'source_src')
        
        # 8. Extract <meta http-equiv="refresh" content="...url=...">
        for tag in soup.find_all('meta'):
            if tag.get('http-equiv', '').lower() == 'refresh':
                content = tag.get('content', '')
                match = re.search(r'url=(.+)', content, re.IGNORECASE)
                if match:
                    self._queue_url(base_url, match.group(1), depth, 'meta_refresh')
        
        # 9. Extract URLs from inline scripts
        for script in soup.find_all('script'):
            if script.string:
                self._extract_urls_from_text(script.string, base_url, depth, 'inline_script')
        
        # 10. Extract URLs from inline styles
        for style in soup.find_all('style'):
            if style.string:
                self._extract_urls_from_text(style.string, base_url, depth, 'inline_style')
        
        # 11. Extract URLs from HTML comments
        for comment in soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text):
            self._extract_urls_from_text(comment, base_url, depth, 'html_comment')
        
        # 12. Extract URLs from HTML attributes that may contain URLs
        url_attributes = ['data-url', 'data-href', 'data-src', 'data-action',
                         'data-endpoint', 'data-api', 'action', 'href', 'src', 
                         'poster', 'formaction', 'cite', 'background']
        
        for tag in soup.find_all():
            for attr in url_attributes:
                if tag.get(attr):
                    self._queue_url(base_url, tag[attr], depth, f'attr_{attr}')
        
        # 13. Extract full URLs from raw HTML via regex
        self._extract_urls_from_text(html, base_url, depth, 'html_regex')

    # ============================================================
    # JS FILE PROCESSING
    # ============================================================
    def _process_js_file(self, url: str, content: str = None):
        """Process a JS file — analyze it and extract URLs"""
        try:
            # Analyze for secrets/APIs
            if content is None:
                response = self.session.get(url, timeout=15, verify=False)
                content = response.text
            
            analysis = self.js_analyzer.analyze_url(url, self.session)
            if analysis.get('apis'):
                for api_url in analysis['apis']:
                    if self._is_same_domain(api_url):
                        self.discovered_urls.add(api_url)
                        self.queue.append((api_url, 0, 'js_api'))
                        self._save_endpoint_incremental(api_url, 'api_endpoints', url)
            
            # Extract URLs from JS content
            self._extract_urls_from_text(content, url, 0, 'js_content')
            
        except Exception as e:
            logger.debug(f"Error processing JS {url}: {e}")

    # ============================================================
    # JSON / XML RESPONSE PROCESSING
    # ============================================================
    def _process_json_response(self, base_url: str, content: str, depth: int):
        """Extract URLs from JSON responses"""
        self._extract_urls_from_text(content, base_url, depth, 'json_response')

    def _process_xml_response(self, base_url: str, content: str, depth: int):
        """Extract URLs from XML responses"""
        self._extract_urls_from_text(content, base_url, depth, 'xml_response')

    # ============================================================
    # URL EXTRACTION HELPERS
    # ============================================================
    def _extract_urls_from_text(self, text: str, base_url: str, depth: int, source: str):
        """Extract all URLs from arbitrary text using regex"""
        if not text:
            return
        
        # Multiple URL patterns
        patterns = [
            # Full URLs
            r'https?://[^\s"\'<>\)\]\}]+',
            # Absolute paths starting with /
            r'["\'\(](/(?:[a-zA-Z0-9_\-./?=&%#:+]+))["\'\)]',
            # Relative paths like ./path or ../path
            r'["\'\(](\.{1,2}/[^\s"\'<>\)\]\}]+)["\'\)]',
            # Common API patterns
            r'["\'](/api/[^\s"\'<>]+)["\']',
            r'["\'](/v\d+/[^\s"\'<>]+)["\']',
            r'["\'](/rest/[^\s"\'<>]+)["\']',
        ]
        
        for pattern in patterns:
            try:
                for match in re.findall(pattern, text, re.IGNORECASE):
                    if isinstance(match, tuple):
                        match = match[0]
                    self._queue_url(base_url, match, depth, source)
            except re.error:
                continue

    def _queue_url(self, base_url: str, raw_url: str, depth: int, source: str):
        """Normalize a URL and add it to the queue if it's same-domain"""
        if not raw_url or not isinstance(raw_url, str):
            return
        
        raw_url = raw_url.strip()
        
        # Skip empty / placeholders
        if not raw_url or raw_url in ['#', '/', '', 'javascript:void(0)',
                                       'javascript:;', 'about:blank']:
            return
        
        # Skip javascript:, mailto:, tel:, data:, etc.
        if any(raw_url.lower().startswith(p) for p in 
               ['javascript:', 'mailto:', 'tel:', 'data:', 'blob:', 'ftp:', 'file:']):
            return
        
        # Skip hash-only
        if raw_url.startswith('#'):
            return
        
        try:
            # Build absolute URL
            absolute_url = urljoin(base_url, raw_url)
            
            # Strip fragments (but keep query strings)
            parsed = urlparse(absolute_url)
            absolute_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                ''  # remove fragment
            ))
            
            # Only keep same-domain URLs
            if not self._is_same_domain(absolute_url):
                return
            
            # Skip by extension
            if self._is_skippable_extension(absolute_url):
                return
            
            # Skip already discovered
            if absolute_url in self.discovered_urls:
                return
            
            # Add to queue
            self.discovered_urls.add(absolute_url)
            self.queue.append((absolute_url, depth + 1, source))
            
            # Save incrementally
            endpoint_type = self._classify_endpoint(absolute_url, '')
            self._save_endpoint_incremental(absolute_url, endpoint_type, source)
            
        except Exception as e:
            logger.debug(f"Error queueing URL {raw_url}: {e}")

    # ============================================================
    # FORM PROCESSING
    # ============================================================
    def _process_form(self, form, base_url: str):
        """Extract a form and its fields"""
        try:
            form_data = {
                'action': urljoin(base_url, form.get('action', '') or base_url),
                'method': form.get('method', 'GET').upper(),
                'fields': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select', 'button']):
                field_name = input_tag.get('name')
                if not field_name:
                    continue
                
                field_type = input_tag.get('type', input_tag.name).lower()
                
                form_data['fields'].append({
                    'name': field_name,
                    'type': field_type,
                    'required': input_tag.get('required') is not None,
                    'value': input_tag.get('value', ''),
                    'sensitive': field_type in ['password', 'email', 'tel', 'number']
                })
            
            if form_data['fields']:
                self.storage.add_form(form_data)
                self.endpoints_by_type['forms'].append({
                    'action': form_data['action'],
                    'method': form_data['method'],
                    'field_count': len(form_data['fields'])
                })
                
        except Exception as e:
            logger.debug(f"Error processing form: {e}")

    # ============================================================
    # DOMAIN FILTERING
    # ============================================================
    def _get_registered_domain(self, host: str) -> str:
        """Extract registered domain (e.g., sub.example.com -> example.com)"""
        host = host.split(':')[0].lower()
        
        # Handle IP addresses
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
            return host
        
        parts = host.split('.')
        if len(parts) >= 2:
            # Handle cases like example.co.uk
            if len(parts) >= 3 and parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu', 'ac']:
                return '.'.join(parts[-3:])
            return '.'.join(parts[-2:])
        return host

    def _is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to the target domain or its subdomains"""
        try:
            parsed = urlparse(url)
            host = parsed.netloc.lower().split(':')[0]
            
            if not host:
                return False
            
            # Direct match
            if host == self.target_host:
                return True
            
            # Subdomain match (e.g., api.example.com belongs to example.com)
            if host.endswith('.' + self.target_domain):
                return True
            
            if host == self.target_domain:
                return True
            
            # Check against third-party block list
            for third_party in self.third_party_domains:
                if host == third_party or host.endswith('.' + third_party):
                    return False
            
            return False
            
        except Exception:
            return False

    def _is_skippable_extension(self, url: str) -> bool:
        """Check if URL extension should be skipped"""
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in self.skip_extensions)

    def _should_skip(self, url: str) -> bool:
        """Check if URL should not be processed"""
        if not url:
            return True
        
        # Skip by extension
        if self._is_skippable_extension(url):
            return True
        
        # Skip by dangerous patterns
        skip_patterns = ['/logout', '/signout', '/exit', '/delete', '/remove']
        for pattern in skip_patterns:
            if pattern in url.lower():
                return True
        
        return False

    # ============================================================
    # ENDPOINT CLASSIFICATION
    # ============================================================
    def _classify_endpoint(self, url: str, content_type: str = '') -> str:
        """Classify an endpoint into a category"""
        url_lower = url.lower()
        content_type = content_type.lower()
        
        if '.js' in url_lower or 'javascript' in content_type:
            return 'js_files'
        if 'json' in content_type or url_lower.endswith('.json'):
            return 'json_endpoints'
        if 'xml' in content_type or url_lower.endswith('.xml'):
            return 'xml_endpoints'
        if any(k in url_lower for k in ['/api/', '/rest/', '/v1/', '/v2/', '/graphql']):
            return 'api_endpoints'
        if 'html' in content_type or any(
            url_lower.endswith(ext) for ext in ['.html', '.htm', '.php', '.asp', '.aspx', '.jsp']
        ) or not urlparse(url).path.split('.')[-1] or '.' not in urlparse(url).path.split('/')[-1]:
            return 'html_pages'
        
        return 'other'

    # ============================================================
    # INCREMENTAL SAVE
    # ============================================================
    def _save_endpoint_incremental(self, url: str, endpoint_type: str, source: str):
        """Save an endpoint to the appropriate list"""
        entry = {
            'url': url,
            'type': endpoint_type,
            'source': source,
            'discovered_at': datetime.now().isoformat()
        }
        if endpoint_type in self.endpoints_by_type:
            self.endpoints_by_type[endpoint_type].append(entry)
        
        # Also save incrementally to disk after every 25 endpoints
        total = sum(len(v) for v in self.endpoints_by_type.values())
        if total % 25 == 0:
            self._save_all_endpoints()

    def _save_all_endpoints(self):
        """Save all discovered endpoints to JSON"""
        try:
            output_dir = self.storage.target_base_dir
            os.makedirs(output_dir, exist_ok=True)
            
            endpoints_file = os.path.join(output_dir, 'discovered_endpoints.json')
            
            data = {
                'target': {
                    'start_url': getattr(self, 'start_url', ''),
                    'host': self.target_host,
                    'domain': self.target_domain
                },
                'timestamp': datetime.now().isoformat(),
                'summary': {
                    'total_visited': len(self.visited_urls),
                    'total_discovered': len(self.discovered_urls),
                    'total_js': len(self.js_files_found),
                    'by_type': {k: len(v) for k, v in self.endpoints_by_type.items()}
                },
                'endpoints': self.endpoints_by_type,
                'all_urls': sorted(list(self.discovered_urls))
            }
            
            with open(endpoints_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            logger.debug(f"Endpoints saved to {endpoints_file}")
            
        except Exception as e:
            logger.error(f"Failed to save endpoints: {e}")

    def _print_discovery_summary(self):
        """Print a summary of discovered endpoints"""
        total = sum(len(v) for v in self.endpoints_by_type.values())
        logger.info("=" * 60)
        logger.info("📊 DISCOVERY SUMMARY")
        logger.info("=" * 60)
        logger.info(f"  Total URLs Visited:     {len(self.visited_urls)}")
        logger.info(f"  Total URLs Discovered:  {len(self.discovered_urls)}")
        logger.info(f"  Total Endpoints Saved:  {total}")
        logger.info(f"  JS Files Found:         {len(self.js_files_found)}")
        logger.info("  By Type:")
        for etype, elist in self.endpoints_by_type.items():
            logger.info(f"    • {etype}: {len(elist)}")
        logger.info("=" * 60)

    # ============================================================
    # VULNERABILITY ANALYSIS (unchanged logic)
    # ============================================================
    def _analyze_vulnerabilities(self):
        """Analyze discovered endpoints for vulnerabilities using Ollama"""
        input_endpoints = self.storage.get_all_input_endpoints()
        if not input_endpoints:
            logger.info("No input endpoints found to analyze")
            return {'vulnerabilities': [], 'total_endpoints': 0}
        
        logger.info(f"📝 Analyzing {len(input_endpoints)} input endpoints with AI...")
        analyzed_results = []
        
        for endpoint in input_endpoints:
            if endpoint.get('type') == 'form':
                for field in endpoint.get('fields', []):
                    if isinstance(field, dict):
                        analysis = self.ollama_analyzer.analyze_endpoint(
                            endpoint.get('action', 'unknown'),
                            endpoint.get('method', 'GET'),
                            [field.get('name', '')],
                            {'action': endpoint.get('action', ''), 'method': endpoint.get('method', 'GET')}
                        )
                        analyzed_results.append(analysis)
            elif endpoint.get('type') == 'url_params':
                analysis = self.ollama_analyzer.analyze_endpoint(
                    endpoint.get('url', ''),
                    'GET',
                    endpoint.get('params', []),
                    None
                )
                analyzed_results.append(analysis)
        
        if analyzed_results:
            report = self.ollama_analyzer.generate_vulnerability_report(analyzed_results)
            self._save_vulnerability_report(report)
            return report
        
        return {'vulnerabilities': [], 'total_endpoints': 0}

    def _save_vulnerability_report(self, report: Dict):
        """Save vulnerability report"""
        try:
            report_dir = os.path.join(self.storage.target_base_dir, 'vulnerabilities')
            os.makedirs(report_dir, exist_ok=True)
            
            with open(os.path.join(report_dir, 'vulnerability_report.json'), 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            with open(os.path.join(report_dir, 'vulnerability_summary.txt'), 'w', encoding='utf-8') as f:
                f.write(self._format_vulnerability_report_text(report))
            
            logger.info(f"📊 Vulnerability report saved")
        except Exception as e:
            logger.error(f"Failed to save vuln report: {e}")

    def _format_vulnerability_report_text(self, report: Dict) -> str:
        """Format report as text"""
        lines = ["=" * 60, "VULNERABILITY REPORT", "=" * 60]
        lines.append(f"Total Endpoints: {report.get('total_endpoints', 0)}")
        lines.append(f"Vulnerabilities: {len(report.get('vulnerabilities', []))}")
        lines.append("")
        
        for i, vuln in enumerate(report.get('top_vulnerabilities', [])[:20], 1):
            lines.append(f"{i}. [{vuln.get('risk_level', '?')}] {vuln.get('type', '?')}")
            lines.append(f"   Endpoint: {vuln.get('endpoint', '?')}")
            lines.append(f"   Parameter: {vuln.get('parameter', '?')}")
            lines.append("")
        
        return "\n".join(lines)

    def _save_exploitation_results(self, results: Dict):
        """Save exploitation results"""
        try:
            exploits_dir = os.path.join(self.storage.target_base_dir, 'exploits')
            os.makedirs(exploits_dir, exist_ok=True)
            
            with open(os.path.join(exploits_dir, 'exploitation_results.json'), 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            logger.info(f"📊 Exploitation results saved")
        except Exception as e:
            logger.error(f"Failed to save exploitation results: {e}")
