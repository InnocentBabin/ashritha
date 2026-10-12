import json
import os
import re
from datetime import datetime
from typing import Dict, List, Optional
import logging
from pathlib import Path
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EndpointStorage:
    def __init__(self, config: Dict, target_url: str = None):
        self.config = config
        self.storage_config = config.get('storage', {})
        self.target_url = target_url
        self.target_folder = self._generate_target_folder(target_url) if target_url else 'default'
        
        self._create_target_directories()
        
        self.endpoints = {
            'urls': [], 'forms': [], 'js_files': [], 'api_endpoints': []
        }
        
        self.js_analysis = {
            'files': [], 'secrets_found': [], 'apis_detected': []
        }
        
        self._load_existing_data()

    def _generate_target_folder(self, target_url: str) -> str:
        try:
            parsed = urlparse(target_url)
            domain = parsed.netloc or parsed.path
            domain = re.sub(r'^www\.', '', domain)
            folder_name = re.sub(r'[^a-zA-Z0-9]', '_', domain)
            return folder_name.strip('_')
        except:
            import hashlib
            return hashlib.md5(target_url.encode()).hexdigest()[:10]

    def _create_target_directories(self):
        self.target_base_dir = os.path.join('output', self.target_folder)
        self.target_dirs = {
            'endpoints': os.path.join(self.target_base_dir, 'endpoints'),
            'js_analysis': os.path.join(self.target_base_dir, 'js_analysis'),
            'reports': os.path.join(self.target_base_dir, 'reports'),
            'attacks': os.path.join(self.target_base_dir, 'attacks'),
            'vulnerabilities': os.path.join(self.target_base_dir, 'vulnerabilities')
        }
        
        for dir_path in self.target_dirs.values():
            Path(dir_path).mkdir(parents=True, exist_ok=True)

    def _load_existing_data(self):
        endpoints_file = os.path.join(self.target_dirs['endpoints'], 'all_endpoints.json')
        if os.path.exists(endpoints_file):
            try:
                with open(endpoints_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.endpoints = data.get('endpoints', self.endpoints)
            except Exception as e:
                logger.warning(f"Failed to load existing data: {e}")

    def add_url(self, url: str, method: str = 'GET', data: Dict = None):
        endpoint_data = {
            'url': url, 'method': method, 
            'timestamp': datetime.now().isoformat(),
            'data': data or {}
        }
        existing = next((e for e in self.endpoints['urls'] if e.get('url') == url), None)
        if not existing:
            self.endpoints['urls'].append(endpoint_data)

    def add_form(self, form_data: Dict):
        self.endpoints['forms'].append({
            'form': form_data,
            'timestamp': datetime.now().isoformat()
        })

    def add_js_file(self, url: str, content: str = None, analysis: Dict = None):
        self.endpoints['js_files'].append({
            'url': url,
            'content_preview': content[:500] if content else None,
            'analysis': analysis or {},
            'timestamp': datetime.now().isoformat()
        })

    def add_api_endpoint(self, url: str, method: str, params: Dict = None):
        self.endpoints['api_endpoints'].append({
            'url': url, 'method': method,
            'params': params or {},
            'timestamp': datetime.now().isoformat()
        })

    def add_secret_finding(self, file_url: str, secret_type: str, value: str, line: int):
        self.js_analysis['secrets_found'].append({
            'file': file_url, 'type': secret_type,
            'value': value[:100], 'line': line,
            'timestamp': datetime.now().isoformat()
        })

    def save(self):
        try:
            # Save all endpoints
            with open(os.path.join(self.target_dirs['endpoints'], 'all_endpoints.json'), 'w', encoding='utf-8') as f:
                json.dump({'endpoints': self.endpoints, 'metadata': {
                    'total_urls': len(self.endpoints['urls']),
                    'total_forms': len(self.endpoints['forms']),
                    'total_js': len(self.endpoints['js_files']),
                    'total_apis': len(self.endpoints['api_endpoints']),
                    'timestamp': datetime.now().isoformat()
                }}, f, indent=2, ensure_ascii=False)
            
            # Save forms
            with open(os.path.join(self.target_dirs['endpoints'], 'forms.json'), 'w', encoding='utf-8') as f:
                json.dump({'forms': self.endpoints['forms']}, f, indent=2, ensure_ascii=False)
            
            # Save JS analysis
            with open(os.path.join(self.target_dirs['js_analysis'], 'analyzed_js.json'), 'w', encoding='utf-8') as f:
                json.dump({'analysis': self.js_analysis}, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            logger.error(f"Failed to save data: {e}")

    def get_all_input_endpoints(self) -> List[Dict]:
        input_endpoints = []
        
        for form_entry in self.endpoints['forms']:
            form = form_entry.get('form', {})
            if form.get('fields'):
                input_endpoints.append({
                    'type': 'form',
                    'action': form.get('action'),
                    'method': form.get('method', 'GET'),
                    'fields': form.get('fields', [])
                })
        
        for url_data in self.endpoints['urls']:
            url = url_data.get('url', '')
            if '?' in url:
                params_part = url.split('?')[1]
                param_names = [p.split('=')[0] for p in params_part.split('&') if '=' in p]
                if param_names:
                    input_endpoints.append({
                        'type': 'url_params',
                        'url': url,
                        'params': param_names
                    })
        
        return input_endpoints

    def generate_report_text(self) -> str:
        lines = []
        lines.append("=" * 60)
        lines.append("VAPT RECONNAISSANCE REPORT")
        lines.append("=" * 60)
        lines.append(f"Target: {self.target_url}")
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append("")
        lines.append("SUMMARY STATISTICS:")
        lines.append(f"  - Total URLs: {len(self.endpoints['urls'])}")
        lines.append(f"  - Total Forms: {len(self.endpoints['forms'])}")
        lines.append(f"  - Total JS Files: {len(self.endpoints['js_files'])}")
        lines.append(f"  - Total API Endpoints: {len(self.endpoints['api_endpoints'])}")
        lines.append(f"  - Secrets Found: {len(self.js_analysis['secrets_found'])}")
        lines.append("")
        lines.append("=" * 60)
        return "\n".join(lines)