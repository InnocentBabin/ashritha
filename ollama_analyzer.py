import json
import logging
from typing import Dict, List, Optional, Any
import re
from datetime import datetime

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
    print("⚠️ Ollama not installed. Install with: pip install ollama")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class OllamaVulnerabilityAnalyzer:
    def __init__(self, model_name: str = "qwen3:30b-32k", 
                 config: Dict = None, host: str = None):
        """
        Initialize Ollama analyzer with optional remote host
        
        Args:
            model_name: Ollama model name
            config: Configuration dictionary
            host: Remote Ollama host (e.g., "http://127.0.0.1:11434")
        """
        self.model_name = model_name
        self.config = config or {}
        self.ollama_available = OLLAMA_AVAILABLE
        
        # Get host from config or parameter
        self.host = host or self.config.get('host', 'http://localhost:11434')
        
        # Initialize Ollama client with remote host
        self.client = None
        if self.ollama_available:
            try:
                self.client = ollama.Client(host=self.host)
                # Test connection
                self.client.list()
                logger.info(f"✅ Ollama connected successfully")
                logger.info(f"   Host: {self.host}")
                logger.info(f"   Model: {self.model_name}")
            except Exception as e:
                logger.warning(f"⚠️ Ollama connection failed: {e}")
                logger.warning(f"   Host: {self.host}")
                self.ollama_available = False
                self.client = None
        
        self.vulnerability_patterns = {
            'sql_injection': {
                'keywords': ['id', 'user', 'query', 'search', 'filter', 'category', 'product', 
                           'email', 'username', 'password', 'name', 'title', 'description'],
                'confidence': 0.7
            },
            'xss': {
                'keywords': ['search', 'comment', 'message', 'feedback', 'name', 'title', 
                           'description', 'content', 'body', 'text'],
                'confidence': 0.6
            },
            'command_injection': {
                'keywords': ['cmd', 'exec', 'command', 'shell', 'system', 'ping', 'nslookup'],
                'confidence': 0.5
            },
            'path_traversal': {
                'keywords': ['file', 'path', 'dir', 'directory', 'download', 'upload', 'include'],
                'confidence': 0.6
            },
            'idor': {
                'keywords': ['id', 'user_id', 'account', 'profile', 'document', 'order', 'invoice'],
                'confidence': 0.7
            },
            'file_upload': {
                'keywords': ['upload', 'file', 'image', 'document', 'attachment', 'media'],
                'confidence': 0.8
            },
            'authentication': {
                'keywords': ['login', 'signin', 'register', 'signup', 'auth', 'password', 'username', 'email'],
                'confidence': 0.9
            }
        }

    def analyze_endpoint(self, url: str, method: str, params: List[str], context: Dict = None) -> Dict[str, Any]:
        """Analyze an endpoint and its parameters for vulnerabilities"""
        result = {
            'url': url,
            'method': method,
            'parameters': params,
            'vulnerabilities': [],
            'risk_score': 0,
            'analysis_timestamp': datetime.now().isoformat(),
            'analysis_method': 'rule_based'
        }
        
        rule_analysis = self._analyze_with_rules(url, method, params, context)
        
        if self.ollama_available and self.client:
            try:
                ai_analysis = self._analyze_with_ollama(url, method, params, context)
                result['analysis_method'] = 'ai_enhanced'
                result['vulnerabilities'] = self._merge_analyses(
                    rule_analysis.get('vulnerabilities', []),
                    ai_analysis.get('vulnerabilities', [])
                )
                result['risk_score'] = max(
                    rule_analysis.get('risk_score', 0),
                    ai_analysis.get('risk_score', 0)
                )
                result['ai_insights'] = ai_analysis.get('insights', [])
                result['ai_raw_response'] = ai_analysis.get('raw_response', '')
            except Exception as e:
                logger.error(f"Ollama analysis failed: {e}")
                result['vulnerabilities'] = rule_analysis.get('vulnerabilities', [])
                result['risk_score'] = rule_analysis.get('risk_score', 0)
        else:
            result['vulnerabilities'] = rule_analysis.get('vulnerabilities', [])
            result['risk_score'] = rule_analysis.get('risk_score', 0)
        
        return result

    def _analyze_with_rules(self, url: str, method: str, params: List[str], context: Dict = None) -> Dict:
        """Rule-based vulnerability analysis"""
        vulnerabilities = []
        risk_score = 0
        
        for param in params:
            param_lower = param.lower()
            
            for vuln_type, pattern in self.vulnerability_patterns.items():
                confidence = 0
                reasons = []
                
                if any(keyword in param_lower for keyword in pattern['keywords']):
                    confidence = max(confidence, pattern.get('confidence', 0.5))
                    reasons.append(f"Parameter '{param}' matches {vuln_type} patterns")
                
                if method == 'POST' and vuln_type in ['authentication', 'file_upload']:
                    confidence = min(confidence + 0.2, 1.0)
                    reasons.append(f"POST method common for {vuln_type}")
                
                if confidence >= 0.5:
                    vulnerabilities.append({
                        'type': vuln_type,
                        'parameter': param,
                        'confidence': confidence,
                        'reasons': reasons,
                        'risk_level': self._calculate_risk_level(confidence, vuln_type)
                    })
                    risk_score = max(risk_score, confidence * 10)
        
        vulnerabilities.sort(key=lambda x: x['confidence'], reverse=True)
        
        return {'vulnerabilities': vulnerabilities[:10], 'risk_score': min(risk_score, 100)}

    def _analyze_with_ollama(self, url: str, method: str, params: List[str], context: Dict = None) -> Dict:
        """Use Ollama AI to analyze vulnerabilities (via remote client)"""
        try:
            prompt = self._build_ollama_prompt(url, method, params, context)
            
            # Use the CLIENT, not the module
            response = self.client.chat(
                model=self.model_name,
                messages=[
                    {
                        'role': 'system',
                        'content': """You are a security expert specializing in web application vulnerability analysis. 
                        Analyze the given endpoint and identify potential vulnerabilities. 
                        Return ONLY valid JSON in your response."""
                    },
                    {
                        'role': 'user',
                        'content': prompt
                    }
                ]
            )
            
            # Access via .message.content (object attribute)
            response_text = response.message.content.strip()
            
            # Try to extract JSON from the response
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                try:
                    analysis = json.loads(json_match.group())
                    parsed = self._parse_ollama_response(analysis)
                    parsed['raw_response'] = response_text
                    return parsed
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse JSON: {e}")
                    return self._parse_text_response(response_text)
            else:
                return self._parse_text_response(response_text)
                
        except Exception as e:
            logger.error(f"Ollama analysis error: {e}")
            return {'vulnerabilities': [], 'risk_score': 0, 'insights': [], 'error': str(e)}

    def _build_ollama_prompt(self, url: str, method: str, params: List[str], context: Dict = None) -> str:
        """Build prompt for Ollama"""
        prompt = f"""Analyze this web endpoint for potential vulnerabilities:

Endpoint URL: {url}
HTTP Method: {method}
Parameters: {', '.join(params) if params else 'None'}
"""
        
        if context:
            prompt += f"""
Context:
- Form Action: {context.get('action', 'N/A')}
- Form Method: {context.get('method', 'N/A')}
"""
        
        prompt += """
Return a JSON response with this exact format:
{
    "vulnerabilities": [
        {
            "type": "sql_injection",
            "parameter": "parameter_name",
            "confidence": 0.85,
            "reasons": ["Reason 1", "Reason 2"],
            "risk_level": "Critical",
            "attack_vector": "How to exploit"
        }
    ],
    "risk_score": 75,
    "insights": ["Security insight 1", "Security insight 2"]
}

Only return valid JSON, no other text.
"""
        return prompt

    def _parse_ollama_response(self, response: Dict) -> Dict:
        """Parse and validate Ollama response"""
        vulnerabilities = []
        for vuln in response.get('vulnerabilities', []):
            if all(key in vuln for key in ['type', 'parameter', 'confidence']):
                vulnerabilities.append({
                    'type': vuln.get('type', 'unknown'),
                    'parameter': vuln.get('parameter', 'unknown'),
                    'confidence': min(max(float(vuln.get('confidence', 0.5)), 0), 1),
                    'reasons': vuln.get('reasons', ['AI analysis']),
                    'risk_level': vuln.get('risk_level', 'Medium'),
                    'attack_vector': vuln.get('attack_vector', '')
                })
        
        return {
            'vulnerabilities': vulnerabilities,
            'risk_score': min(max(int(response.get('risk_score', 0)), 0), 100),
            'insights': response.get('insights', [])
        }

    def _parse_text_response(self, text: str) -> Dict:
        """Parse plain text response from Ollama when JSON parsing fails"""
        vulnerabilities = []
        
        vuln_types = ['sql_injection', 'xss', 'command_injection', 'path_traversal', 'idor', 'file_upload', 'authentication']
        
        for vuln_type in vuln_types:
            if vuln_type in text.lower():
                param_match = re.search(r'parameter[:]?\s*(\w+)', text, re.IGNORECASE)
                param = param_match.group(1) if param_match else 'unknown'
                
                vulnerabilities.append({
                    'type': vuln_type,
                    'parameter': param,
                    'confidence': 0.6,
                    'reasons': ['Detected in AI analysis'],
                    'risk_level': 'Medium',
                    'attack_vector': 'Further analysis required'
                })
        
        return {
            'vulnerabilities': vulnerabilities,
            'risk_score': len(vulnerabilities) * 10,
            'insights': ['AI analysis completed'],
            'raw_response': text
        }

    def _merge_analyses(self, rule_analysis: List[Dict], ai_analysis: List[Dict]) -> List[Dict]:
        """Merge rule-based and AI analyses, removing duplicates"""
        merged = []
        seen = set()
        
        for vuln in rule_analysis:
            key = f"{vuln['type']}_{vuln['parameter']}"
            if key not in seen:
                seen.add(key)
                merged.append(vuln)
        
        for vuln in ai_analysis:
            key = f"{vuln['type']}_{vuln['parameter']}"
            if key not in seen:
                seen.add(key)
                merged.append(vuln)
            else:
                for existing in merged:
                    if f"{existing['type']}_{existing['parameter']}" == key:
                        if vuln.get('confidence', 0) > existing.get('confidence', 0):
                            existing.update(vuln)
        
        merged.sort(key=lambda x: x.get('confidence', 0), reverse=True)
        return merged[:10]

    def _calculate_risk_level(self, confidence: float, vuln_type: str) -> str:
        """Calculate risk level based on confidence"""
        if confidence >= 0.8:
            return 'Critical'
        elif confidence >= 0.6:
            return 'High'
        elif confidence >= 0.4:
            return 'Medium'
        else:
            return 'Low'

    def generate_vulnerability_report(self, analyzed_fields: List[Dict]) -> Dict:
        """Generate a comprehensive vulnerability report"""
        report = {
            'total_endpoints': len(analyzed_fields),
            'vulnerabilities': [],
            'risk_breakdown': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0},
            'top_vulnerabilities': [],
            'recommendations': []
        }
        
        all_vulns = []
        for field in analyzed_fields:
            for vuln in field.get('vulnerabilities', []):
                vuln_copy = vuln.copy()
                vuln_copy['endpoint'] = field.get('url', 'unknown')
                vuln_copy['method'] = field.get('method', 'GET')
                
                risk_level = vuln.get('risk_level', 'Medium')
                report['risk_breakdown'][risk_level] = report['risk_breakdown'].get(risk_level, 0) + 1
                all_vulns.append(vuln_copy)
        
        risk_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        all_vulns.sort(key=lambda x: risk_order.get(x.get('risk_level', 'Low'), 4))
        
        report['vulnerabilities'] = all_vulns
        report['top_vulnerabilities'] = all_vulns[:20]
        
        recommendations_map = {
            'sql_injection': ["Use parameterized queries", "Implement input validation", "Use stored procedures"],
            'xss': ["Use Content Security Policy", "Implement output encoding", "Use XSS protection libraries"],
            'command_injection': ["Avoid system() with user input", "Use allowlists", "Implement input validation"],
            'path_traversal': ["Validate file paths", "Use allowlists", "Store files outside web root"],
            'idor': ["Implement proper authorization", "Use UUIDs instead of numeric IDs", "Validate user permissions"],
            'file_upload': ["Validate file type and size", "Store files outside web root", "Use antivirus scanning"],
            'authentication': ["Implement MFA", "Use strong password policies", "Implement account lockout"]
        }
        
        for vuln_type in set([v.get('type', '') for v in all_vulns if v.get('type')]):
            report['recommendations'].extend(recommendations_map.get(vuln_type, ["Review and secure this vulnerability"]))
        
        report['recommendations'] = list(set(report['recommendations']))[:10]
        return report

    def test_ollama_connection(self) -> bool:
        """Test if Ollama is running and accessible"""
        if not self.ollama_available or not self.client:
            return False
        try:
            self.client.list()
            logger.info(f"✅ Ollama connection successful")
            logger.info(f"   Host: {self.host}")
            return True
        except Exception as e:
            logger.error(f"❌ Ollama connection failed: {e}")
            return False