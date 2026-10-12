#!/usr/bin/env python3
"""
Test script for Remote Ollama integration
"""

import sys
import yaml
import os

try:
    import ollama
except ImportError:
    print("❌ Ollama package not installed. Run: pip install ollama")
    sys.exit(1)


def test_ollama():
    print("=" * 60)
    print("Testing REMOTE Ollama Connection")
    print("=" * 60)
    
    # Load config
    config = {}
    if os.path.exists('config.yaml'):
        with open('config.yaml', 'r') as f:
            config = yaml.safe_load(f)
    
    ollama_config = config.get('ollama', {})
    host = ollama_config.get('host', 'http://localhost:11434')
    model_name = ollama_config.get('model', 'qwen3:30b-32k')
    
    print(f"\n🔗 Host:  {host}")
    print(f"🤖 Model: {model_name}")
    print("-" * 60)
    
    # Create client with remote host
    try:
        client = ollama.Client(host=host)
        print(f"✅ Client created for host: {host}")
    except Exception as e:
        print(f"❌ Failed to create client: {e}")
        return False
    
    # List models on remote server
    print("\n📋 Listing models on remote server...")
    try:
        models_response = client.list()
        model_names = []
        
        # Handle both dict and object responses
        if hasattr(models_response, 'models'):
            model_names = [m.model for m in models_response.models]
        elif isinstance(models_response, dict):
            model_names = [m.get('model', m.get('name', '')) for m in models_response.get('models', [])]
        
        print(f"✅ Available models on remote server:")
        for name in model_names:
            print(f"   - {name}")
        
        if model_name not in model_names:
            print(f"\n⚠️ Model '{model_name}' not found on remote server!")
            print(f"   Available: {model_names}")
            if model_names:
                print(f"   Would you like to use '{model_names[0]}' instead?")
                model_name = model_names[0]
            else:
                print("❌ No models available. Pull one on the remote server.")
                return False
        else:
            print(f"\n✅ Model '{model_name}' is available on the remote server!")
            
    except Exception as e:
        print(f"❌ Failed to list models: {e}")
        return False
    
    # Test chat
    print("\n" + "-" * 60)
    print("🧪 Testing chat with remote Ollama...")
    print("-" * 60)
    
    try:
        response = client.chat(
            model=model_name,
            messages=[{'role': 'user', 'content': 'Hello, are you working?'}]
        )
        
        content = response.message.content if hasattr(response, 'message') else response.get('message', {}).get('content', '')
        
        print(f"✅ Response received!")
        print(f"   Preview: {content[:100]}...")
        
    except Exception as e:
        print(f"❌ Chat failed: {e}")
        return False
    
    # Test vulnerability analysis
    print("\n" + "-" * 60)
    print("🧪 Testing vulnerability analysis...")
    print("-" * 60)
    
    test_url = "http://testasp.vulnweb.com/Templatize.asp?item=html/about.html"
    test_params = ["item"]
    
    prompt = f"""Analyze this endpoint for vulnerabilities:
Endpoint: {test_url}
Method: GET
Parameters: {', '.join(test_params)}

Return JSON with:
{{
    "vulnerabilities": [
        {{
            "type": "sql_injection|xss|path_traversal|command_injection",
            "parameter": "parameter_name",
            "confidence": 0.0-1.0,
            "risk_level": "Critical|High|Medium|Low",
            "reasons": ["reason1", "reason2"]
        }}
    ],
    "risk_score": 0-100
}}"""
    
    try:
        response = client.chat(
            model=model_name,
            messages=[
                {
                    'role': 'system',
                    'content': "You are a security expert. Analyze the endpoint and identify vulnerabilities. Return ONLY valid JSON."
                },
                {
                    'role': 'user',
                    'content': prompt
                }
            ]
        )
        
        content = response.message.content if hasattr(response, 'message') else response.get('message', {}).get('content', '')
        
        print("✅ Vulnerability analysis complete!")
        print(f"\n📊 Analysis Result:")
        print("-" * 60)
        print(content[:800])
        print("-" * 60)
        
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        return False
    
    print("\n" + "=" * 60)
    print("✅ All tests passed! Remote Ollama is ready.")
    print("=" * 60)
    return True


if __name__ == "__main__":
    success = test_ollama()
    sys.exit(0 if success else 1)