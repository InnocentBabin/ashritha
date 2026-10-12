import re
import time
import json
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
from collections import deque
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import os
from datetime import datetime

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
        self.priority_endpoints = self.recon_config.get('priority_endpoints', [])
        
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.queue = deque()
        self.js_files_found: Set[str] = set()
        
        self.js_analyzer = JSAnalyzer(config, storage)
        self.form_analyzer = FormAnalyzer(config, storage)
        
        # Get Ollama config with remote host
        ollama_config = config.get('ollama', {})
        ollama_host = ollama_config.get('host', 'http://localhost:11434')
        ollama_model = ollama_config.get('model', 'qwen3:30b-32k')
        
        logger.info(f"🔗 Connecting to Ollama at: {ollama_host}")
        
        # Pass host to analyzer
        self.ollama_analyzer = OllamaVulnerabilityAnalyzer(
            model_name=ollama_model,
            config=ollama_config,
            host=ollama_host
        )
        
        self.exploit_engine = None
        self.exploit_results = None

    def discover(self, start_url: str) -> Dict:
        """Start the discovery process"""
        logger.info(f"🚀 Starting reconnaissance on: {start_url}")
        
        # Add priority endpoints
        for endpoint in self.priority_endpoints:
            priority_url = urljoin(start_url, endpoint)
            if priority_url not in self.discovered_urls:
                self.queue.append((priority_url, 0))
                self.discovered_urls.add(priority_url)
        
        # Add start URL
        if start_url not in self.discovered_urls:
            self.queue.append((start_url, 0))
            self.discovered_urls.add(start_url)
        
        # Process queue with thread pool
        with ThreadPoolExecutor(max_workers=self.concurrent_requests) as executor:
            futures = []
            
            while self.queue and len(self.visited_urls) < self.max_pages:
                url, depth = self.queue.popleft()
                
                if url in self.visited_urls or self._should_ignore(url):
                    continue
                
                future = executor.submit(self._process_url, url, depth)
                futures.append(future)
                
                if len(futures) >= self.concurrent_requests * 2:
                    for f in as_completed(futures[:self.concurrent_requests]):
                        try:
                            f.result()
                        except Exception as e:
                            logger.error(f"Error: {e}")
                    futures = futures[self.concurrent_requests:]
        
        # Process remaining futures
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"Error: {e}")
        
        # Save all data
        self.storage.save()
        
        # Run AI vulnerability analysis
        logger.info("🧠 Running AI vulnerability analysis...")
        vuln_report = self._analyze_vulnerabilities()
        
        # Run automated exploitation
        if vuln_report and self.config.get('exploitation', {}).get('enabled', True):
            logger.info("🔨 Starting automated exploitation...")
            self.exploit_engine = ExploitEngine(self.config, self.session, self.storage)
            
            # Get all vulnerabilities from the report
            all_vulns = vuln_report.get('vulnerabilities', [])
            if all_vulns:
                self.exploit_results = self.exploit_engine.exploit_all(all_vulns)
                # Print exploitation summary
                self.exploit_engine.print_summary()
                # Save exploitation results
                self._save_exploitation_results(self.exploit_results)
            else:
                logger.info("✅ No vulnerabilities found to exploit")
        
        return {
            'visited': len(self.visited_urls),
            'discovered': len(self.discovered_urls),
            'js_files': self.js_analyzer.stats['total_files'],
            'secrets': self.js_analyzer.stats['secrets_found'],
            'vulnerabilities': len(vuln_report.get('vulnerabilities', [])) if vuln_report else 0,
            'successful_exploits': len(self.exploit_results.get('successful_exploits', [])) if self.exploit_results else 0
        }

    def _process_url(self, url: str, depth: int):
        """Process a single URL"""
        if url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        logger.info(f"🔍 Processing ({depth}): {url}")
        
        try:
            # Check if it's a JS file
            if url.endswith('.js') or '.js?' in url or url.endswith('.js.map'):
                self._process_js_file(url)
                return
            
            # Fetch the page
            response = self.session.get(url, timeout=30, allow_redirects=True, verify=False)
            
            if response.status_code != 200:
                logger.debug(f"Non-200 response: {response.status_code} - {url}")
                return
            
            # Check content type for JavaScript
            content_type = response.headers.get('content-type', '').lower()
            if 'javascript' in content_type or 'application/json' in content_type:
                self._process_js_content(url, response.text)
                return
            
            # Store URL
            self.storage.add_url(url, 'GET', {
                'status_code': response.status_code,
                'content_type': content_type,
                'content_length': len(response.content)
            })
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'lxml')
            
            # Extract JavaScript files
            self._extract_js_files(soup, url)
            
            # Process forms
            self._process_forms(soup, url)
            
            # Process all links
            self._process_links(soup, url, depth)
            
            # Process API endpoints
            self._process_api_endpoints(soup, url)
            
            # Process inline JavaScript
            self._process_inline_js(response.text, url)
            
        except requests.RequestException as e:
            logger.debug(f"Request error for {url}: {e}")
        except Exception as e:
            logger.error(f"Error processing {url}: {e}")

    def _extract_js_files(self, soup: BeautifulSoup, base_url: str):
        """Extract all JavaScript files from HTML"""
        js_sources = []
        
        # Find all script tags with src
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                absolute_url = urljoin(base_url, src)
                js_sources.append(absolute_url)
        
        # Check for preload links
        for link in soup.find_all('link', {'rel': ['preload', 'modulepreload', 'prefetch']}):
            href = link.get('href')
            if href and '.js' in href:
                absolute_url = urljoin(base_url, href)
                js_sources.append(absolute_url)
        
        # Process each JS file
        for js_url in js_sources:
            if js_url not in self.js_files_found:
                self.js_files_found.add(js_url)
                self._process_js_file(js_url)

    def _process_js_file(self, url: str):
        """Process a JavaScript file"""
        try:
            self.js_analyzer.analyze_url(url, self.session)
        except Exception as e:
            logger.error(f"Error processing JS {url}: {e}")

    def _process_js_content(self, url: str, content: str):
        """Process JavaScript content directly"""
        try:
            analysis = self.js_analyzer._analyze_content(content, url)
            if analysis.get('secrets') or analysis.get('apis'):
                self.storage.add_js_file(url, content[:500], analysis)
        except Exception as e:
            logger.error(f"Error processing JS content: {e}")

    def _process_forms(self, soup: BeautifulSoup, base_url: str):
        """Process forms found in HTML"""
        forms = soup.find_all('form')
        
        for form in forms:
            form_data = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'fields': []
            }
            
            # Extract input fields
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                field_name = input_tag.get('name', '')
                if field_name:
                    field_data = {
                        'name': field_name,
                        'type': input_tag.get('type', 'text'),
                        'required': input_tag.get('required') is not None,
                        'value': input_tag.get('value', ''),
                        'sensitive': input_tag.get('type', '') in ['password', 'email', 'tel']
                    }
                    form_data['fields'].append(field_data)
            
            # Store form if it has fields
            if form_data['fields']:
                self.storage.add_form(form_data)

    def _process_links(self, soup: BeautifulSoup, base_url: str, current_depth: int):
        """Process all links found in HTML"""
        if current_depth >= self.max_depth:
            return
        
        for link in soup.find_all(['a', 'link']):
            href = link.get('href')
            if not href:
                continue
            
            absolute_url = urljoin(base_url, href)
            
            if absolute_url in self.discovered_urls or self._should_ignore(absolute_url):
                continue
            
            self.discovered_urls.add(absolute_url)
            self.queue.append((absolute_url, current_depth + 1))
            self.storage.add_url(absolute_url, 'GET', {'discovered_from': base_url})

    def _process_api_endpoints(self, soup: BeautifulSoup, base_url: str):
        """Process API endpoints found in HTML"""
        api_patterns = [
            r'/api/', r'/rest/', r'/v\d+/', r'/graphql',
            r'/swagger', r'/docs', r'/json', r'/data'
        ]
        
        for script in soup.find_all('script'):
            if script.string:
                text = script.string
                for pattern in api_patterns:
                    if pattern in text:
                        urls = re.findall(r'["\']([^"\']*' + pattern.replace('/', '\\/') + r'[^"\']*)["\']', text)
                        for url in urls:
                            if url and not url.startswith('//'):
                                absolute_url = urljoin(base_url, url)
                                self.storage.add_api_endpoint(absolute_url, 'GET', {})
                                self.discovered_urls.add(absolute_url)

    def _process_inline_js(self, html: str, base_url: str):
        """Process inline JavaScript for secrets and endpoints"""
        script_pattern = r'<script[^>]*>([\s\S]*?)<\/script>'
        scripts = re.findall(script_pattern, html)
        
        for script in scripts:
            if script.strip():
                analysis = self.js_analyzer._analyze_content(script, base_url)
                if analysis.get('secrets'):
                    for secret in analysis['secrets']:
                        self.storage.add_secret_finding(
                            base_url,
                            secret.get('type', 'Unknown'),
                            secret.get('value', ''),
                            secret.get('line', 0)
                        )

    def _should_ignore(self, url: str) -> bool:
        """Check if URL should be ignored"""
        for ext in self.ignore_extensions:
            if url.lower().endswith(ext):
                return True
        
        ignore_patterns = [
            '/logout', '/signout', '.ico', '.svg', '/cdn-cgi/',
            'data:', 'javascript:', 'mailto:', 'tel:'
        ]
        for pattern in ignore_patterns:
            if pattern in url.lower():
                return True
        
        return False

    def _analyze_vulnerabilities(self):
        """Analyze discovered endpoints for vulnerabilities using Ollama"""
        logger.info("🧠 Analyzing endpoints for vulnerabilities...")
        
        input_endpoints = self.storage.get_all_input_endpoints()
        if not input_endpoints:
            logger.info("No input endpoints found to analyze")
            return {'vulnerabilities': [], 'total_endpoints': 0}
        
        logger.info(f"📝 Found {len(input_endpoints)} input endpoints to analyze")
        analyzed_results = []
        
        for endpoint in input_endpoints:
            if endpoint.get('type') == 'form':
                fields = endpoint.get('fields', [])
                for field in fields:
                    if isinstance(field, dict):
                        params = [field.get('name', '')]
                        context = {
                            'action': endpoint.get('action', ''),
                            'method': endpoint.get('method', 'GET'),
                            'has_csrf': self._check_csrf_protection(field)
                        }
                        
                        analysis = self.ollama_analyzer.analyze_endpoint(
                            endpoint.get('action', 'unknown'),
                            endpoint.get('method', 'GET'),
                            params,
                            context
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
            logger.info(f"✅ Found {len(report.get('vulnerabilities', []))} potential vulnerabilities")
            return report
        
        return {'vulnerabilities': [], 'total_endpoints': 0}

    def _check_csrf_protection(self, field: Dict) -> bool:
        """Check if a field suggests CSRF protection"""
        field_name = field.get('name', '').lower()
        csrf_patterns = ['csrf', 'token', 'authenticity_token', '_token', 'csrfmiddlewaretoken']
        return any(pattern in field_name for pattern in csrf_patterns)

    def _save_vulnerability_report(self, report: Dict):
        """Save vulnerability report to file"""
        try:
            report_dir = self.storage.target_dirs.get('vulnerabilities', 
                                                      os.path.join(self.storage.target_base_dir, 'vulnerabilities'))
            os.makedirs(report_dir, exist_ok=True)
            
            report_file = os.path.join(report_dir, 'vulnerability_report.json')
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            logger.info(f"📊 Vulnerability report saved to {report_file}")
            
            # Summary text
            text_file = os.path.join(report_dir, 'vulnerability_summary.txt')
            with open(text_file, 'w', encoding='utf-8') as f:
                f.write(self._format_vulnerability_report_text(report))
            logger.info(f"📄 Vulnerability summary saved to {text_file}")
            
        except Exception as e:
            logger.error(f"Failed to save vulnerability report: {e}")

    def _format_vulnerability_report_text(self, report: Dict) -> str:
        """Format vulnerability report as text"""
        lines = []
        lines.append("=" * 80)
        lines.append("VULNERABILITY ANALYSIS REPORT - AI Powered")
        lines.append("=" * 80)
        lines.append(f"Total Endpoints Analyzed: {report.get('total_endpoints', 0)}")
        lines.append("")
        
        lines.append("RISK BREAKDOWN:")
        for risk, count in report.get('risk_breakdown', {}).items():
            lines.append(f"  {risk}: {count}")
        lines.append("")
        
        lines.append("TOP VULNERABILITIES:")
        for i, vuln in enumerate(report.get('top_vulnerabilities', [])[:10], 1):
            lines.append(f"  {i}. [{vuln.get('risk_level', 'Unknown')}] {vuln.get('type', 'Unknown')}")
            lines.append(f"     Endpoint: {vuln.get('endpoint', 'Unknown')}")
            lines.append(f"     Parameter: {vuln.get('parameter', 'Unknown')}")
            lines.append(f"     Confidence: {vuln.get('confidence', 0) * 100:.0f}%")
            if vuln.get('attack_vector'):
                lines.append(f"     Attack: {vuln.get('attack_vector', '')}")
            lines.append("")
        
        lines.append("RECOMMENDATIONS:")
        for rec in report.get('recommendations', []):
            lines.append(f"  - {rec}")
        lines.append("=" * 80)
        return "\n".join(lines)

    def _save_exploitation_results(self, results: Dict):
        """Save exploitation results to storage"""
        try:
            exploits_dir = os.path.join(self.storage.target_base_dir, 'exploits')
            os.makedirs(exploits_dir, exist_ok=True)
            
            # Save as JSON
            with open(os.path.join(exploits_dir, 'exploitation_results.json'), 'w', encoding='utf-8') as f:
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'results': results,
                    'stats': results.get('stats', {})
                }, f, indent=2, ensure_ascii=False)
            
            # Save working payloads
            successful = results.get('successful_exploits', [])
            if successful:
                payloads_file = os.path.join(exploits_dir, 'working_payloads.txt')
                with open(payloads_file, 'w', encoding='utf-8') as f:
                    f.write("WORKING PAYLOADS\n")
                    f.write("=" * 80 + "\n")
                    for exploit in successful:
                        f.write(f"\n[{exploit.get('vuln_type', 'Unknown').upper()}]\n")
                        f.write(f"Endpoint: {exploit.get('endpoint', 'Unknown')}\n")
                        f.write(f"Parameter: {exploit.get('parameter', 'Unknown')}\n")
                        f.write(f"Payload: {exploit.get('payload', 'Unknown')}\n")
                        f.write(f"Status: {exploit.get('status_code', 'Unknown')}\n")
                        if exploit.get('evidence'):
                            f.write(f"Evidence: {exploit.get('evidence', '')[:200]}...\n")
                        f.write("-" * 40 + "\n")
                logger.info(f"📝 Working payloads saved to {payloads_file}")
            
            logger.info(f"✅ Exploitation results saved to {exploits_dir}")
            
        except Exception as e:
            logger.error(f"Failed to save exploitation results: {e}")

    def _format_exploitation_summary(self, results: Dict) -> str:
        """Format exploitation summary as text"""
        lines = []
        lines.append("=" * 80)
        lines.append("AUTOMATED EXPLOITATION COMPLETE")
        lines.append("=" * 80)
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append("")
        
        stats = results.get('stats', {})
        lines.append("STATISTICS:")
        lines.append(f"  Total Payloads Tested: {stats.get('total_tested', 0)}")
        lines.append(f"  Successful Exploits:   {stats.get('successful_exploits', 0)}")
        lines.append(f"  Failed Attempts:       {stats.get('failed_attempts', 0)}")
        lines.append("")
        
        successful = results.get('successful_exploits', [])
        if successful:
            lines.append("SUCCESSFUL EXPLOITS:")
            lines.append("-" * 80)
            
            for i, exploit in enumerate(successful, 1):
                lines.append(f"\n{i}. [{exploit.get('vuln_type', 'Unknown').upper()}]")
                lines.append(f"   Endpoint:  {exploit.get('endpoint', 'Unknown')}")
                lines.append(f"   Parameter: {exploit.get('parameter', 'Unknown')}")
                lines.append(f"   Payload:   {exploit.get('payload', 'Unknown')}")
                lines.append(f"   Status:    {exploit.get('status_code', 'Unknown')}")
                if exploit.get('evidence'):
                    lines.append(f"   Evidence:  {exploit.get('evidence', '')[:200]}...")
        
        lines.append("\n" + "=" * 80)
        return "\n".join(lines)

    def get_summary(self) -> Dict:
        """Get summary of all findings"""
        return {
            'urls_visited': len(self.visited_urls),
            'urls_discovered': len(self.discovered_urls),
            'js_files': self.js_analyzer.stats['total_files'],
            'secrets': self.js_analyzer.stats['secrets_found'],
            'vulnerabilities': len(self.exploit_results.get('successful_exploits', [])) if self.exploit_results else 0,
            'successful_exploits': len(self.exploit_results.get('successful_exploits', [])) if self.exploit_results else 0
        }