#!/usr/bin/env python3
"""
Ashritha - AI-Powered VAPT Automation Tool
Usage: python main.py recon https://target.com -u username -p password
"""

import warnings
import urllib3
import click
import logging
import sys
import os
import yaml
from typing import Dict
from datetime import datetime
from colorama import init, Fore, Style
import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
warnings.filterwarnings('ignore', category=InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from login_engine import LoginEngine
from session_manager import SessionManager, SessionContext
from recon_engine import ReconEngine
from endpoint_storage import EndpointStorage

init(autoreset=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Silence Redis connection warnings (falls back to memory automatically)
# logging.getLogger('session_manager').setLevel(logging.ERROR)


def print_banner():
    """Print the Ashritha banner"""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════╗
{Fore.CYAN}║                                                                          ║
{Fore.YELLOW}║      █████╗ ███████╗██╗  ██╗██████╗ ██╗████████╗██╗  ██╗ █████╗          ║
{Fore.YELLOW}║     ██╔══██╗██╔════╝██║  ██║██╔══██╗██║╚══██╔══╝██║  ██║██╔══██╗         ║
{Fore.YELLOW}║     ███████║███████╗███████║██████╔╝██║   ██║   ███████║███████║         ║
{Fore.YELLOW}║     ██╔══██║╚════██║██╔══██║██╔══██╗██║   ██║   ██╔══██║██╔══██║         ║
{Fore.YELLOW}║     ██║  ██║███████║██║  ██║██║  ██║██║   ██║   ██║  ██║██║  ██║         ║
{Fore.YELLOW}║     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝         ║
{Fore.CYAN}║                                                                          ║
{Fore.GREEN}║        🚀 AI-Powered VAPT Automation Tool with Ollama 🚀                 ║
{Fore.MAGENTA}║         Automated Reconnaissance • Exploitation • AI                     ║
{Fore.CYAN}║                                                                          ║
{Fore.WHITE}║  Version: 2.0.0                                                          ║
{Fore.WHITE}║  Author : BABIN BM                                                       ║
{Fore.WHITE}║  Profile: https://www.linkedin.com/in/babin-bm                           ║
{Fore.WHITE}║  Purpose: Authorized Security Testing Only                               ║
{Fore.CYAN}║                                                                          ║
{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
{Fore.RED}⚠️  LEGAL WARNING: Use only on systems you own or have written permission!{Style.RESET_ALL}
{Fore.RED}⚠️  Unauthorized access to computer systems is illegal and punishable by law.{Style.RESET_ALL}

{Fore.YELLOW}[*]{Style.RESET_ALL} Starting Ashritha VAPT Engine...
{Fore.CYAN}{'─' * 76}{Style.RESET_ALL}
"""
    print(banner)


class VAPTReconCLI:
    """Main CLI class for Ashritha VAPT Recon with AI and Exploitation"""
    
    def __init__(self, config_path: str = 'config.yaml'):
        self.config = self._load_config(config_path)
        self.session_manager = SessionManager(**self.config.get('session', {}))
        self.recon_engine = None
        
    def _load_config(self, config_path: str) -> dict:
        """Load configuration from YAML file"""
        default_config = {
            'session': {
                'enabled': False,
                'ttl_seconds': 3600,
                'refresh_threshold': 300,
                'redis_host': 'localhost',
                'redis_port': 6379,
                'redis_db': 0
            },
            'ollama': {
                'model': 'IHA089/drana-infinity-3b:3b',
                'host': 'http://127.0.0.1:11434',
                'enabled': True,
                'timeout_seconds': 60,
                'max_tokens': 2000,
                'temperature': 0.3
            },
            'exploitation': {
                'enabled': True,
                'max_payloads_per_vuln': 20,
                'timeout_seconds': 15,
                'safe_mode': True,
                'detect_errors': True
            },
            'tech_fingerprint': {
                'enabled': True,
                'run_wappalyzer': True,
                'run_whatweb': True,
                'wappalyzer_timeout': 60,
                'whatweb_timeout': 60,
                'whatweb_aggression': 3
            },
            'cve_matching': {
                'enabled': True,
                'use_nvd': False,
                'max_cves_per_tech': 10
            },
            'recon': {
                'max_depth': 5,
                'max_pages': 1000,
                'timeout_seconds': 30,
                'concurrent_requests': 10,
                'user_agent': 'Ashritha-VAPT-Bot/2.0',
                'ignore_extensions': [
                    '.jpg', '.jpeg', '.png', '.gif', '.mp4', '.mp3', 
                    '.pdf', '.doc', '.docx', '.ico', '.svg', '.woff', '.ttf'
                ],
                'priority_endpoints': [
                    '/api/', '/rest/', '/graphql', '/admin', 
                    '/dashboard', '/swagger', '/docs', '/v1/', '/v2/'
                ]
            },
            'js_analysis': {
                'secrets_patterns': {
                    'api_key': [
                        r'[a-zA-Z0-9]{32,}',
                        r'AIza[0-9A-Za-z-_]{35}',
                        r'sk-[a-zA-Z0-9]{48}',
                        r'sk_live_[a-zA-Z0-9]{24}',
                        r'pk_live_[a-zA-Z0-9]{24}',
                        r'AKIA[0-9A-Z]{16}',
                        r'secret_[a-zA-Z0-9]{32}',
                        r'token_[a-zA-Z0-9]{32}'
                    ],
                    'credentials': [
                        r'password\s*[:=]\s*["\']([^"\']+)["\']',
                        r'username\s*[:=]\s*["\']([^"\']+)["\']',
                        r'auth\s*[:=]\s*["\']([^"\']+)["\']',
                        r'authorization\s*[:=]\s*["\']([^"\']+)["\']',
                        r'Basic\s+[a-zA-Z0-9+/=]{20,}',
                        r'Bearer\s+[a-zA-Z0-9._-]{20,}'
                    ],
                    'cloud_services': [
                        r'twilio\.(accountSid|authToken)\s*[:=]\s*["\']([^"\']+)["\']',
                        r'SENDGRID_API_KEY\s*[:=]\s*["\']([^"\']+)["\']',
                        r'AZURE_[A-Z_]+_KEY\s*[:=]\s*["\']([^"\']+)["\']',
                        r'AWS_[A-Z_]+_KEY\s*[:=]\s*["\']([^"\']+)["\']',
                        r'GCP_[A-Z_]+_KEY\s*[:=]\s*["\']([^"\']+)["\']',
                        r'openai\s*[:=]\s*["\']([^"\']+)["\']'
                    ]
                }
            },
            'storage': {
                'endpoints_file': 'endpoints/all_endpoints.json',
                'categorized_file': 'endpoints/categorized_endpoints.json',
                'js_analysis_file': 'js_analysis/analyzed_js.json',
                'forms_file': 'endpoints/forms.json',
                'report_file': 'reports/recon_report.json'
            }
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f)
                    for key, value in default_config.items():
                        if key not in config:
                            config[key] = value
                        elif isinstance(value, dict):
                            for sub_key, sub_value in value.items():
                                if sub_key not in config[key]:
                                    config[key][sub_key] = sub_value
                    return config
            else:
                logger.warning(f"Config file {config_path} not found, using defaults")
                return default_config
        except Exception as e:
            logger.warning(f"Error loading config: {e}, using defaults")
            return default_config

    def recon(self, target_url: str, username: str = None, password: str = None, 
              role: str = 'default', force_login: bool = False) -> bool:
        """Run reconnaissance with AI analysis and automated exploitation"""
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}🔍 Ashritha VAPT - Reconnaissance Engine")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.WHITE}Target: {Fore.GREEN}{target_url}")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        # Handle session
        session = None
        if username and password:
            existing_session = self.session_manager.get_session(username, role)
            if existing_session and not force_login:
                session = existing_session
                print(f"{Fore.GREEN}✅ Using existing session for {username}")
            else:
                print(f"{Fore.WHITE}🔐 Logging in as {username}...")
                login_engine = LoginEngine(self.config)
                result = login_engine.login(target_url, username, password)
                if result:
                    session = SessionContext(
                        session_id=f"{role}_{username}_{int(datetime.now().timestamp())}",
                        cookies=result.get('cookies', {}),
                        headers=result.get('headers', {}),
                        username=username,
                        expires_at=datetime.now().timestamp() + 3600,
                        login_url=target_url
                    )
                    self.session_manager.store_session(session, role)
                    print(f"{Fore.GREEN}✅ Login successful!")
                else:
                    print(f"{Fore.RED}❌ Login failed")
                    return False
        
        # Create HTTP session
        http_session = requests.Session()
        http_session.verify = False
        http_session.headers.update({
            'User-Agent': self.config.get('recon', {}).get('user_agent', 
                'Ashritha-VAPT-Bot/2.0'),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        if session:
            http_session.cookies.update(session.cookies)
            http_session.headers.update(session.headers)
            print(f"{Fore.GREEN}✅ Using authenticated session\n")
        else:
            print(f"{Fore.YELLOW}⚠️  Running without authentication\n")
        
        # Initialize storage
        storage = EndpointStorage(self.config, target_url)
        
        # Initialize recon engine
        self.recon_engine = ReconEngine(self.config, storage, http_session)
        
        print(f"{Fore.WHITE}🚀 Starting discovery with AI analysis...")
        start_time = datetime.now()
        
        try:
            results = self.recon_engine.discover(target_url)
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            # Display summary
            self._display_results(results, storage, duration)
            
            return True
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}⚠️  Recon stopped by user")
            storage.save()
            return False
        except Exception as e:
            print(f"{Fore.RED}❌ Recon failed: {e}")
            logger.error(f"Recon error: {e}", exc_info=True)
            storage.save()
            return False

    def _display_results(self, results: Dict, storage: EndpointStorage, duration: float):
        """Display comprehensive results"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.GREEN}✅ Ashritha VAPT - Reconnaissance Complete!")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.WHITE}📊 Statistics:")
        print(f"  {Fore.GREEN}• URLs Visited:          {results.get('visited', 0)}")
        print(f"  {Fore.GREEN}• URLs Discovered:       {results.get('discovered', 0)}")
        print(f"  {Fore.GREEN}• JS Files Analyzed:     {results.get('js_files', 0)}")
        print(f"  {Fore.GREEN}• Secrets Found:         {results.get('secrets', 0)}")
        print(f"  {Fore.GREEN}• Vulnerabilities Found: {results.get('vulnerabilities', 0)}")
        print(f"  {Fore.GREEN}• Successful Exploits:   {results.get('successful_exploits', 0)}")
        print(f"  {Fore.GREEN}• Duration:              {duration:.2f} seconds")
        print(f"{Fore.CYAN}{'='*60}")
        
        if results.get('secrets', 0) > 0:
            print(f"\n{Fore.RED}⚠️  {results['secrets']} SECRETS FOUND - Check output/{storage.target_folder}/js_analysis/")
        
        if results.get('successful_exploits', 0) > 0:
            print(f"\n{Fore.RED}🔴 {results['successful_exploits']} VULNERABILITIES SUCCESSFULLY EXPLOITED!")
            print(f"   Check output/{storage.target_folder}/exploits/ for details")
            
            if self.recon_engine and self.recon_engine.exploit_results:
                successful = self.recon_engine.exploit_results.get('successful_exploits', [])
                print(f"\n{Fore.WHITE}📝 Working Payloads:")
                for exploit in successful[:5]:
                    vuln_type = exploit.get('vuln_type', 'Unknown').upper()
                    endpoint = exploit.get('endpoint', 'Unknown')
                    payload = exploit.get('payload', 'Unknown')
                    print(f"  {Fore.YELLOW}→ [{vuln_type}] {endpoint}")
                    print(f"    Payload: {payload[:80]}...")
                if len(successful) > 5:
                    print(f"  {Fore.YELLOW}→ ... and {len(successful) - 5} more exploits")
        else:
            print(f"\n{Fore.GREEN}✅ No vulnerabilities were exploitable")
        
        if self.recon_engine and hasattr(self.recon_engine, 'tech_fingerprinter') and self.recon_engine.tech_fingerprinter:
            technologies = self.recon_engine.tech_fingerprinter.extract_technologies()
            if technologies:
                print(f"\n{Fore.WHITE}🔧 Technology Stack ({len(technologies)} detected):")
                for tech in technologies[:10]:
                    name = tech.get('name', 'Unknown')
                    version = tech.get('version', '')
                    source = tech.get('source', '')
                    print(f"  {Fore.CYAN}• {name} {version} ({source})")
                if len(technologies) > 10:
                    print(f"  {Fore.CYAN}• ... and {len(technologies) - 10} more")
        
        print(f"\n{Fore.WHITE}📁 Output Directory:")
        print(f"  {Fore.GREEN}output/{storage.target_folder}/")
        
        print(f"\n{Fore.WHITE}📄 Reports:")
        print(f"  {Fore.GREEN}• output/{storage.target_folder}/vulnerabilities/vulnerability_summary.txt")
        print(f"  {Fore.GREEN}• output/{storage.target_folder}/exploits/exploitation_summary.txt")
        print(f"  {Fore.GREEN}• output/{storage.target_folder}/exploits/working_payloads.txt")
        print(f"  {Fore.GREEN}• output/{storage.target_folder}/tech_analysis/tech_summary.txt")
        
        print(f"{Fore.CYAN}{'='*60}\n")
        
        if self.recon_engine and self.recon_engine.js_analyzer:
            self.recon_engine.js_analyzer.print_summary()


@click.group()
def cli():
    """Ashritha - AI-Powered VAPT Automation Tool"""
    pass


@cli.command()
@click.argument('target_url')
@click.option('-u', '--username', help='Username for authentication')
@click.option('-p', '--password', help='Password for authentication')
@click.option('-r', '--role', default='default', help='Role for session')
@click.option('-f', '--force', is_flag=True, help='Force fresh login')
@click.option('--config', default='config.yaml', help='Config file path')
@click.option('--verbose', is_flag=True, help='Enable verbose logging')
@click.option('--no-exploit', is_flag=True, help='Disable automated exploitation')
def recon(target_url, username, password, role, force, config, verbose, no_exploit):
    """
    Run reconnaissance with AI vulnerability analysis and automated exploitation
    
    Examples:
    
    # Basic scan with authentication
    python main.py recon https://example.com -u admin -p password123
    
    # Scan without exploitation
    python main.py recon https://example.com -u admin -p password123 --no-exploit
    
    # Verbose mode for debugging
    python main.py recon https://example.com -u admin -p password123 --verbose
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    cli_instance = VAPTReconCLI(config)
    
    if no_exploit:
        cli_instance.config['exploitation']['enabled'] = False
    
    success = cli_instance.recon(target_url, username, password, role, force)
    sys.exit(0 if success else 1)


@cli.command()
@click.argument('target_url')
@click.option('-u', '--username', help='Username for authentication')
@click.option('-p', '--password', help='Password for authentication')
@click.option('--config', default='config.yaml', help='Config file path')
def quick(target_url, username, password, config):
    """
    Quick scan with default settings
    
    Example:
        python main.py quick https://example.com -u admin -p password123
    """
    cli_instance = VAPTReconCLI(config)
    success = cli_instance.recon(
        target_url=target_url,
        username=username,
        password=password,
        role='default',
        force_login=False
    )
    sys.exit(0 if success else 1)


@cli.command()
@click.argument('target_folder', default=None, required=False)
@click.option('--format', default='summary', help='Output format: summary, json, or csv')
def report(target_folder, format):
    """
    Generate report from recon results
    
    Examples:
    
    # Show summary report (latest target)
    python main.py report
    
    # Show JSON report
    python main.py report --format json
    
    # Show report for specific target
    python main.py report example_com
    """
    try:
        if target_folder:
            report_file = f"output/{target_folder}/reports/recon_report.json"
        else:
            output_dir = "output"
            if os.path.exists(output_dir):
                folders = [f for f in os.listdir(output_dir) 
                          if os.path.isdir(os.path.join(output_dir, f))]
                if folders:
                    folders.sort(key=lambda x: os.path.getmtime(os.path.join(output_dir, x)), reverse=True)
                    report_file = f"output/{folders[0]}/reports/recon_report.json"
                else:
                    print("No reports found")
                    sys.exit(1)
            else:
                print("No reports found")
                sys.exit(1)
        
        if not os.path.exists(report_file):
            print(f"Report file not found: {report_file}")
            sys.exit(1)
            
        with open(report_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if format == 'json':
            print(json.dumps(data, indent=2))
        elif format == 'csv':
            print("Category,Count")
            metadata = data.get('metadata', {})
            print(f"URLs,{metadata.get('total_urls_visited', 0)}")
            print(f"JS Files,{metadata.get('js_files_analyzed', 0)}")
            print(f"Secrets,{metadata.get('secrets_found', 0)}")
        else:
            print(data.get('report', 'No report available'))
            
    except FileNotFoundError:
        print(f"Report file not found: {report_file}")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading report: {e}")
        sys.exit(1)


if __name__ == '__main__':
    print_banner()
    cli()