import re
import json
import requests
from typing import Dict, List, Set
from urllib.parse import urlparse, urljoin
import logging
import jsbeautifier
from collections import defaultdict
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

warnings.filterwarnings('ignore', message='Unverified HTTPS request')
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class JSAnalyzer:
    def __init__(self, config: Dict, storage):
        self.config = config
        self.storage = storage
        self.js_config = config.get('js_analysis', {})
        self.secret_patterns = self.js_config.get('secrets_patterns', {})
        
        self.processed_files: Set[str] = set()
        
        self.safe_file_patterns = [
            'google-analytics', 'googletagmanager', 'gtag', 'facebook', 'twitter',
            'linkedin', 'hotjar', 'clarity', 'mixpanel', 'segment', 'sentry',
            'wp-content/plugins/', 'wp-content/themes/', 'wp-includes/',
            'elementor', 'woocommerce', 'yoast', 'cdn.', 'cloudflare',
            'googleapis', 'gstatic', 'bootstrap', 'jquery', 'react', 'vue', 'angular'
        ]
        
        self.false_positive_patterns = [
            r'UA-\d+-\d+', r'GTM-\w+', r'G-\w+', r'INVALID_GA4_', r'GA4_',
            r'console\.log', r'test_', r'demo_', r'example_', r'placeholder',
            r'\$\{.*?\}', r'process\.env\..*', r'wp_', r'elementor'
        ]
        
        self.stats = {
            'total_files': 0,
            'total_lines': 0,
            'secrets_found': 0,
            'apis_detected': 0,
            'false_positives_skipped': 0,
            'safe_files_skipped': 0
        }
        
        self.file_findings = defaultdict(lambda: {
            'secrets': [], 'apis': [], 'urls': [], 'cloud_services': []
        })

    def is_safe_file(self, url: str) -> bool:
        url_lower = url.lower()
        for pattern in self.safe_file_patterns:
            if pattern in url_lower:
                return True
        if '.min.js' in url_lower:
            return True
        return False

    def is_false_positive(self, value: str) -> bool:
        if not value or len(value) < 8:
            return True
        
        value_str = str(value).strip()
        for pattern in self.false_positive_patterns:
            if re.search(pattern, value_str, re.IGNORECASE):
                return True
        
        if re.match(r'^[A-Za-z0-9]{8,}$', value_str) and not any(c.isdigit() for c in value_str):
            return True
        
        return False

    def analyze_url(self, url: str, session) -> Dict:
        try:
            if url in self.processed_files:
                return {}
            
            if self.is_safe_file(url):
                logger.info(f"⏭️ Skipping safe file: {url}")
                self.stats['safe_files_skipped'] += 1
                return {}
            
            logger.info(f"📜 Analyzing JS file: {url}")
            
            response = session.get(url, timeout=30, verify=False)
            if response.status_code != 200:
                return {}
            
            content = response.text
            self.stats['total_files'] += 1
            self.processed_files.add(url)
            
            try:
                beautified = jsbeautifier.beautify(content)
            except:
                beautified = content
            
            analysis = self._analyze_content(beautified, url)
            
            if analysis.get('secrets') or analysis.get('apis'):
                self.file_findings[url] = {
                    'secrets': analysis.get('secrets', []),
                    'apis': analysis.get('apis', []),
                    'urls': analysis.get('urls', []),
                    'cloud_services': analysis.get('cloud_services', [])
                }
                self.storage.add_js_file(url, content[:500], analysis)
                
                if analysis.get('secrets'):
                    logger.warning(f"🔐 Found {len(analysis['secrets'])} secrets in {url}")
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing JS {url}: {e}")
            return {}

    def _analyze_content(self, content: str, url: str) -> Dict:
        analysis = {
            'secrets': [], 'apis': [], 'urls': [], 'cloud_services': []
        }
        
        found_secrets = set()
        lines = content.split('\n')
        self.stats['total_lines'] += len(lines)
        
        for line_num, line in enumerate(lines, 1):
            if not line.strip() or line.strip().startswith('//'):
                continue
            
            secrets = self._find_secrets(line, line_num, url)
            for secret in secrets:
                key = f"{secret['type']}_{secret['value']}"
                if key not in found_secrets and not self.is_false_positive(secret['value']):
                    found_secrets.add(key)
                    analysis['secrets'].append(secret)
                    self.stats['secrets_found'] += 1
            
            apis = self._find_api_endpoints(line, url)
            if apis:
                analysis['apis'].extend(apis)
                self.stats['apis_detected'] += len(apis)
        
        analysis['secrets'] = self._deduplicate_secrets(analysis['secrets'])
        analysis['apis'] = list(set(analysis['apis']))
        return analysis

    def _find_secrets(self, line: str, line_num: int, file_url: str) -> List[Dict]:
        secrets = []
        
        for secret_type, patterns in self.secret_patterns.items():
            for pattern in patterns:
                try:
                    matches = re.findall(pattern, line, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            for m in reversed(match):
                                if m and len(str(m)) > 5:
                                    match = m
                                    break
                            else:
                                match = match[0] if match else None
                        
                        if not match:
                            continue
                        
                        match_str = str(match).strip()
                        if len(match_str) < 8:
                            continue
                        
                        secrets.append({
                            'type': secret_type,
                            'value': match_str[:100],
                            'line': line_num,
                            'file': file_url
                        })
                except re.error:
                    continue
        
        return secrets

    def _find_api_endpoints(self, line: str, base_url: str) -> List[str]:
        apis = []
        patterns = [
            r'(?:url|endpoint)\s*[:=]\s*["\']([^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\s*\.\s*(?:get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
            r'api\s*\.\s*(?:get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            try:
                matches = re.findall(pattern, line, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    if not match or len(match) < 3:
                        continue
                    if 'wp-content' in match or 'wp-includes' in match:
                        continue
                    if match.startswith('/'):
                        parsed_base = urlparse(base_url)
                        match = f"{parsed_base.scheme}://{parsed_base.netloc}{match}"
                    if 'api' in match.lower() or 'rest' in match.lower():
                        apis.append(match)
            except re.error:
                continue
        
        return apis

    def _deduplicate_secrets(self, secrets: List[Dict]) -> List[Dict]:
        seen = set()
        unique = []
        for secret in secrets:
            key = f"{secret.get('type', '')}_{secret.get('value', '')}"
            if key not in seen:
                seen.add(key)
                unique.append(secret)
        return unique

    def print_summary(self):
        print("\n" + "=" * 60)
        print("JAVASCRIPT ANALYSIS SUMMARY")
        print("=" * 60)
        print(f"📊 Files Analyzed:         {self.stats['total_files']}")
        print(f"🔐 Secrets Found:          {self.stats['secrets_found']}")
        print(f"🔄 API Endpoints Found:    {self.stats['apis_detected']}")
        print(f"⏭️ False Positives Skipped: {self.stats['false_positives_skipped']}")
        print(f"🔒 Safe Files Skipped:     {self.stats['safe_files_skipped']}")
        print("=" * 60)
        
        if self.file_findings:
            print("\n📜 FINDINGS PER FILE:")
            for url, findings in self.file_findings.items():
                secrets_count = len(findings.get('secrets', []))
                apis_count = len(findings.get('apis', []))
                if secrets_count > 0 or apis_count > 0:
                    print(f"\n  📄 {url}")
                    if secrets_count > 0:
                        print(f"    🔐 {secrets_count} secrets found")
                        for secret in findings.get('secrets', [])[:3]:
                            print(f"      - {secret.get('type', 'Unknown')}: {secret.get('value', '')[:50]}...")
                    if apis_count > 0:
                        print(f"    🔄 {apis_count} API endpoints found")
                        for api in findings.get('apis', [])[:3]:
                            print(f"      - {api}")
        print("=" * 60)