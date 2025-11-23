#!/usr/bin/env python3
"""
AI-Powered Vulnerability Analyzer using Ollama Cloud
Provides intelligent analysis, false positive detection, and enhanced reporting
"""

import os
import json
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv
import ollama
from colorama import Fore, Style, init

init(autoreset=True)
load_dotenv()


class OllamaAnalyzer:
    """AI-powered analyzer using Ollama Cloud"""
    
    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None, model: Optional[str] = None):
        """
        Initialize Ollama Cloud client
        
        Args:
            api_key: Ollama Cloud API key (defaults to env var)
            base_url: Ollama Cloud base URL (defaults to env var)
            model: Model to use (defaults to env var or llama3.1:8b)
        """
        self.api_key = api_key or os.getenv('OLLAMA_API_KEY')
        self.base_url = base_url or os.getenv('OLLAMA_BASE_URL', 'https://api.ollama.cloud')
        self.model = model or os.getenv('OLLAMA_MODEL', 'llama3.1:8b')
        
        if not self.api_key:
            raise ValueError(
                "Ollama API key not found. Please set OLLAMA_API_KEY in .env file or pass it to the constructor."
            )
        
        # Configure Ollama client
        self.client = ollama.Client(
            host=self.base_url,
            headers={'Authorization': f'Bearer {self.api_key}'}
        )
        
        print(f"{Fore.CYAN}[AI] Initialized Ollama Cloud with model: {self.model}{Style.RESET_ALL}")
    
    def _chat(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Send a chat request to Ollama Cloud
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt for context
            
        Returns:
            AI response text
        """
        messages = []
        
        if system_prompt:
            messages.append({
                'role': 'system',
                'content': system_prompt
            })
        
        messages.append({
            'role': 'user',
            'content': prompt
        })
        
        try:
            response = self.client.chat(
                model=self.model,
                messages=messages
            )
            return response['message']['content']
        except Exception as e:
            print(f"{Fore.RED}[AI] Error communicating with Ollama Cloud: {str(e)}{Style.RESET_ALL}")
            return ""
    
    def analyze_vulnerability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a vulnerability finding with AI
        
        Args:
            vulnerability: Vulnerability data dictionary
            
        Returns:
            Enhanced vulnerability data with AI analysis
        """
        print(f"{Fore.YELLOW}[AI] Analyzing vulnerability: {vulnerability.get('type', 'Unknown')}{Style.RESET_ALL}")
        
        system_prompt = """You are a cybersecurity expert specializing in vulnerability analysis.
Analyze the provided vulnerability finding and provide:
1. Severity assessment (Critical/High/Medium/Low)
2. Exploitability score (1-10)
3. Potential impact
4. Recommended remediation steps
5. Whether this is likely a false positive (yes/no with confidence %)

Be concise and technical. Format your response as JSON."""
        
        prompt = f"""Analyze this vulnerability finding:

Type: {vulnerability.get('type', 'Unknown')}
URL: {vulnerability.get('url', 'N/A')}
Parameter: {vulnerability.get('parameter', 'N/A')}
Payload: {vulnerability.get('payload', 'N/A')}
Current Severity: {vulnerability.get('severity', 'Unknown')}
Evidence: {vulnerability.get('evidence', 'N/A')}

Provide your analysis in JSON format with keys: severity, exploitability_score, impact, remediation, is_false_positive, confidence."""
        
        response = self._chat(prompt, system_prompt)
        
        # Try to parse JSON response
        try:
            # Extract JSON from response (handle markdown code blocks)
            if '```json' in response:
                json_str = response.split('```json')[1].split('```')[0].strip()
            elif '```' in response:
                json_str = response.split('```')[1].split('```')[0].strip()
            else:
                json_str = response.strip()
            
            analysis = json.loads(json_str)
            vulnerability['ai_analysis'] = analysis
            
            # Update severity if AI suggests different
            if 'severity' in analysis and analysis['severity'] != vulnerability.get('severity'):
                vulnerability['original_severity'] = vulnerability.get('severity')
                vulnerability['severity'] = analysis['severity']
                print(f"{Fore.CYAN}[AI] Updated severity: {analysis['severity']}{Style.RESET_ALL}")
            
        except json.JSONDecodeError:
            # If JSON parsing fails, store raw response
            vulnerability['ai_analysis'] = {'raw_response': response}
            print(f"{Fore.YELLOW}[AI] Could not parse JSON, stored raw response{Style.RESET_ALL}")
        
        return vulnerability
    
    def detect_false_positives(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze multiple vulnerabilities to detect false positives
        
        Args:
            vulnerabilities: List of vulnerability findings
            
        Returns:
            Filtered list with false positives marked
        """
        print(f"{Fore.CYAN}[AI] Analyzing {len(vulnerabilities)} findings for false positives...{Style.RESET_ALL}")
        
        system_prompt = """You are a security researcher expert at identifying false positives in automated vulnerability scans.
Analyze each finding and determine if it's a real vulnerability or a false positive.
Consider:
- Whether user input can actually reach the dangerous function
- If proper sanitization exists
- Context of the code usage
- Common false positive patterns

Respond with a JSON array of objects with keys: index, is_false_positive, confidence, reason."""
        
        # Prepare summary of vulnerabilities
        vuln_summary = []
        for idx, vuln in enumerate(vulnerabilities):
            vuln_summary.append({
                'index': idx,
                'type': vuln.get('type'),
                'url': vuln.get('url'),
                'parameter': vuln.get('parameter'),
                'payload': vuln.get('payload'),
                'evidence': vuln.get('evidence', '')[:200]  # Limit evidence length
            })
        
        prompt = f"""Analyze these vulnerability findings for false positives:

{json.dumps(vuln_summary, indent=2)}

For each finding, determine if it's a false positive. Return JSON array."""
        
        response = self._chat(prompt, system_prompt)
        
        try:
            # Extract JSON from response
            if '```json' in response:
                json_str = response.split('```json')[1].split('```')[0].strip()
            elif '```' in response:
                json_str = response.split('```')[1].split('```')[0].strip()
            else:
                json_str = response.strip()
            
            analysis_results = json.loads(json_str)
            
            # Apply false positive detection results
            for result in analysis_results:
                idx = result.get('index')
                if idx is not None and idx < len(vulnerabilities):
                    vulnerabilities[idx]['false_positive_check'] = {
                        'is_false_positive': result.get('is_false_positive', False),
                        'confidence': result.get('confidence', 0),
                        'reason': result.get('reason', '')
                    }
                    
                    if result.get('is_false_positive'):
                        print(f"{Fore.YELLOW}[AI] Marked finding #{idx} as likely false positive ({result.get('confidence')}% confidence){Style.RESET_ALL}")
        
        except json.JSONDecodeError:
            print(f"{Fore.YELLOW}[AI] Could not parse false positive analysis{Style.RESET_ALL}")
        
        return vulnerabilities
    
    def analyze_javascript_code(self, js_code: str, url: str) -> Dict[str, Any]:
        """
        Analyze JavaScript code for DOM XSS vulnerabilities
        
        Args:
            js_code: JavaScript code to analyze
            url: URL where the code was found
            
        Returns:
            Analysis results with potential vulnerabilities
        """
        print(f"{Fore.YELLOW}[AI] Analyzing JavaScript code from {url}{Style.RESET_ALL}")
        
        system_prompt = """You are a JavaScript security expert specializing in DOM XSS detection.
Analyze the provided JavaScript code for potential DOM XSS vulnerabilities.
Look for:
- Dangerous sinks (innerHTML, eval, setTimeout with strings, etc.)
- User-controlled sources (location.*, document.cookie, postMessage, etc.)
- Data flow from sources to sinks
- Missing sanitization

Provide detailed analysis in JSON format with keys: vulnerabilities (array), risk_level, recommendations."""
        
        # Limit code length to avoid token limits
        code_snippet = js_code[:3000] if len(js_code) > 3000 else js_code
        
        prompt = f"""Analyze this JavaScript code for DOM XSS vulnerabilities:

URL: {url}

Code:
```javascript
{code_snippet}
```

Identify any potential DOM XSS vulnerabilities. Return JSON format."""
        
        response = self._chat(prompt, system_prompt)
        
        try:
            # Extract JSON from response
            if '```json' in response:
                json_str = response.split('```json')[1].split('```')[0].strip()
            elif '```' in response:
                json_str = response.split('```')[1].split('```')[0].strip()
            else:
                json_str = response.strip()
            
            analysis = json.loads(json_str)
            analysis['url'] = url
            analysis['code_length'] = len(js_code)
            
            if analysis.get('vulnerabilities'):
                print(f"{Fore.RED}[AI] Found {len(analysis['vulnerabilities'])} potential DOM XSS issues{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[AI] No DOM XSS vulnerabilities detected{Style.RESET_ALL}")
            
            return analysis
            
        except json.JSONDecodeError:
            return {
                'url': url,
                'error': 'Could not parse analysis',
                'raw_response': response
            }
    
    def generate_executive_summary(self, scan_results: Dict[str, Any]) -> str:
        """
        Generate an executive summary of scan results
        
        Args:
            scan_results: Complete scan results dictionary
            
        Returns:
            Executive summary text
        """
        print(f"{Fore.CYAN}[AI] Generating executive summary...{Style.RESET_ALL}")
        
        system_prompt = """You are a cybersecurity consultant writing an executive summary for a security assessment.
Create a clear, professional summary that:
1. Highlights the most critical findings
2. Explains business impact in non-technical terms
3. Provides prioritized recommendations
4. Includes an overall risk assessment

Keep it concise (300-500 words) and executive-friendly."""
        
        # Prepare scan summary
        vuln_count = len(scan_results.get('vulnerabilities', []))
        critical = sum(1 for v in scan_results.get('vulnerabilities', []) if v.get('severity') == 'Critical')
        high = sum(1 for v in scan_results.get('vulnerabilities', []) if v.get('severity') == 'High')
        medium = sum(1 for v in scan_results.get('vulnerabilities', []) if v.get('severity') == 'Medium')
        low = sum(1 for v in scan_results.get('vulnerabilities', []) if v.get('severity') == 'Low')
        
        # Get top vulnerabilities
        top_vulns = []
        for vuln in scan_results.get('vulnerabilities', [])[:5]:
            top_vulns.append({
                'type': vuln.get('type'),
                'severity': vuln.get('severity'),
                'url': vuln.get('url')
            })
        
        prompt = f"""Generate an executive summary for this security assessment:

Target: {scan_results.get('target', 'Unknown')}
Scan Date: {scan_results.get('scan_date', 'Unknown')}

Vulnerability Summary:
- Total: {vuln_count}
- Critical: {critical}
- High: {high}
- Medium: {medium}
- Low: {low}

Top Findings:
{json.dumps(top_vulns, indent=2)}

Reconnaissance Results:
- Subdomains: {len(scan_results.get('reconnaissance', {}).get('subdomains', []))}
- Directories: {len(scan_results.get('reconnaissance', {}).get('directories', []))}

Create a professional executive summary."""
        
        summary = self._chat(prompt, system_prompt)
        return summary
    
    def suggest_payloads(self, vulnerability_type: str, context: Dict[str, Any]) -> List[str]:
        """
        Generate context-aware exploit payloads
        
        Args:
            vulnerability_type: Type of vulnerability (XSS, SQLi, etc.)
            context: Context information (URL, parameter, technology stack, etc.)
            
        Returns:
            List of suggested payloads
        """
        print(f"{Fore.YELLOW}[AI] Generating payloads for {vulnerability_type}{Style.RESET_ALL}")
        
        system_prompt = """You are a penetration testing expert.
Generate effective, context-aware exploit payloads for the given vulnerability type.
Consider the technology stack, input context, and potential filters.
Provide 5-10 diverse payloads that test different bypass techniques.

Return a JSON array of payload strings."""
        
        prompt = f"""Generate exploit payloads for:

Vulnerability Type: {vulnerability_type}
URL: {context.get('url', 'N/A')}
Parameter: {context.get('parameter', 'N/A')}
Technology: {context.get('technology', 'Unknown')}
Input Context: {context.get('input_context', 'Unknown')}

Generate diverse, effective payloads. Return as JSON array of strings."""
        
        response = self._chat(prompt, system_prompt)
        
        try:
            # Extract JSON from response
            if '```json' in response:
                json_str = response.split('```json')[1].split('```')[0].strip()
            elif '```' in response:
                json_str = response.split('```')[1].split('```')[0].strip()
            else:
                json_str = response.strip()
            
            payloads = json.loads(json_str)
            
            if isinstance(payloads, list):
                print(f"{Fore.GREEN}[AI] Generated {len(payloads)} payloads{Style.RESET_ALL}")
                return payloads
            else:
                return []
                
        except json.JSONDecodeError:
            print(f"{Fore.YELLOW}[AI] Could not parse payload suggestions{Style.RESET_ALL}")
            return []


def main():
    """Test the AI analyzer"""
    print(f"{Fore.CYAN}Testing Ollama Cloud AI Analyzer{Style.RESET_ALL}\n")
    
    try:
        analyzer = OllamaAnalyzer()
        
        # Test vulnerability analysis
        test_vuln = {
            'type': 'DOM XSS',
            'url': 'https://example.com/page.html',
            'parameter': 'search',
            'payload': '<script>alert(1)</script>',
            'severity': 'High',
            'evidence': 'innerHTML assignment with location.search'
        }
        
        print(f"\n{Fore.CYAN}Test 1: Vulnerability Analysis{Style.RESET_ALL}")
        result = analyzer.analyze_vulnerability(test_vuln)
        print(json.dumps(result.get('ai_analysis', {}), indent=2))
        
        print(f"\n{Fore.CYAN}Test 2: JavaScript Code Analysis{Style.RESET_ALL}")
        test_code = """
        var search = location.search;
        document.getElementById('output').innerHTML = search;
        """
        js_analysis = analyzer.analyze_javascript_code(test_code, 'https://example.com/test.js')
        print(json.dumps(js_analysis, indent=2))
        
        print(f"\n{Fore.GREEN}AI Analyzer tests complete!{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Make sure to set OLLAMA_API_KEY in your .env file{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
