from typing import Dict, List
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FormAnalyzer:
    def __init__(self, config: Dict, storage):
        self.config = config
        self.storage = storage
    
    def analyze_form(self, form_data: Dict) -> Dict:
        analysis = {
            'security_issues': [],
            'input_types': [],
            'sensitive_fields': [],
            'csrf_protection': False,
            'input_validation': False
        }
        
        fields = form_data.get('fields', [])
        
        for field in fields:
            field_type = field.get('type', '')
            field_name = field.get('name', '')
            
            if field_type not in analysis['input_types']:
                analysis['input_types'].append(field_type)
            
            if field.get('sensitive', False) or field_type in ['password', 'email', 'tel']:
                analysis['sensitive_fields'].append(field_name)
            
            if 'csrf' in field_name.lower() or 'token' in field_name.lower():
                analysis['csrf_protection'] = True
            
            if field.get('required') or field.get('pattern') or field.get('minlength'):
                analysis['input_validation'] = True
            
            if field_type == 'text' and any(x in field_name.lower() for x in ['email', 'user']):
                analysis['security_issues'].append({
                    'type': 'input_validation',
                    'field': field_name,
                    'issue': 'User input field may be vulnerable to injection'
                })
        
        return analysis
    
    def extract_input_fields(self, forms: List[Dict]) -> List[Dict]:
        input_fields = []
        
        for form_entry in forms:
            form_data = form_entry.get('form', {})
            action = form_data.get('action', 'unknown')
            method = form_data.get('method', 'GET')
            
            for field in form_data.get('fields', []):
                input_fields.append({
                    'form_action': action,
                    'form_method': method,
                    'field_name': field.get('name', ''),
                    'field_type': field.get('type', 'text'),
                    'required': field.get('required', False),
                    'sensitive': field.get('sensitive', False)
                })
        
        return input_fields
    
    def get_attack_surface(self) -> Dict:
        forms = self.storage.endpoints.get('forms', [])
        
        attack_surface = {
            'total_forms': len(forms),
            'total_inputs': 0,
            'sensitive_inputs': 0,
            'file_uploads': 0,
            'csrf_protected': 0,
            'vulnerable_inputs': []
        }
        
        for form_entry in forms:
            form_data = form_entry.get('form', {})
            fields = form_data.get('fields', [])
            
            attack_surface['total_inputs'] += len(fields)
            
            for field in fields:
                field_type = field.get('type', '')
                field_name = field.get('name', '')
                
                if field_type == 'file':
                    attack_surface['file_uploads'] += 1
                
                if field.get('sensitive', False):
                    attack_surface['sensitive_inputs'] += 1
                
                vulnerable_patterns = [
                    ('sql', ['id', 'user', 'name', 'query']),
                    ('xss', ['name', 'comment', 'message', 'search']),
                    ('path_traversal', ['file', 'path', 'dir']),
                    ('command_injection', ['cmd', 'exec', 'command'])
                ]
                
                for vuln_type, patterns in vulnerable_patterns:
                    if any(pattern in field_name.lower() for pattern in patterns):
                        if field_type not in ['hidden', 'password', 'email']:
                            attack_surface['vulnerable_inputs'].append({
                                'field': field_name,
                                'type': field_type,
                                'vulnerability': vuln_type,
                                'form_action': form_data.get('action', 'unknown')
                            })
        
        return attack_surface