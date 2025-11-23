# 🤖 AI-Enhanced Features with Ollama Cloud

This toolkit now includes powerful AI capabilities powered by **Ollama Cloud**, providing intelligent vulnerability analysis, false positive detection, and enhanced reporting.

## 🌟 Features

### 1. **AI-Powered Vulnerability Analysis**
- Intelligent severity assessment
- Exploitability scoring (1-10 scale)
- Detailed impact analysis
- Context-aware remediation recommendations

### 2. **False Positive Detection**
- Automatic detection of likely false positives
- Confidence scoring for each finding
- Detailed reasoning for false positive classification
- Filters out high-confidence false positives automatically

### 3. **JavaScript Code Analysis**
- Deep analysis of JavaScript code for DOM XSS
- Source-to-sink data flow analysis
- Detection of dangerous patterns with context
- Identification of user-controlled inputs

### 4. **AI-Generated Reports**
- Executive summaries in natural language
- Professional vulnerability reports
- Beautiful HTML reports with AI insights
- Prioritized recommendations

### 5. **Context-Aware Payload Generation**
- AI-suggested exploit payloads
- Technology-specific bypass techniques
- Diverse payload variations
- Context-aware testing strategies

---

## 🚀 Quick Start

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 2: Configure Ollama Cloud

1. **Get your Ollama Cloud API key** from your account dashboard
2. **Copy the example environment file:**
   ```bash
   cp .env.example .env
   ```

3. **Edit `.env` and add your credentials:**
   ```bash
   # Ollama Cloud Configuration
   OLLAMA_API_KEY=your_actual_api_key_here
   OLLAMA_BASE_URL=https://api.ollama.cloud
   OLLAMA_MODEL=llama3.1:8b
   ```

### Step 3: Run AI-Enhanced Scans

```bash
# Full AI-enhanced scan
python tools/ai_vulnerability_scanner.py -t example.com

# AI-enhanced XSS scan only
python scanners/xss_scanner_ai.py -u https://example.com

# Generate AI report from existing scan
python reports/ai_report_generator.py -i results/scan_results.json
```

---

## 📚 Detailed Usage

### AI-Enhanced Vulnerability Scanner

The main AI-enhanced scanner orchestrates all scanning modules with AI analysis:

```bash
# Basic usage
python tools/ai_vulnerability_scanner.py -t target.com

# Custom output directory
python tools/ai_vulnerability_scanner.py -t target.com -o ./my_results

# Skip reconnaissance phase
python tools/ai_vulnerability_scanner.py -t target.com --skip-recon

# Disable AI (use traditional scanning only)
python tools/ai_vulnerability_scanner.py -t target.com --no-ai
```

**What it does:**
1. Runs reconnaissance (subdomains, tech detection)
2. Performs AI-enhanced vulnerability scans
3. Analyzes each finding with AI
4. Detects and filters false positives
5. Generates comprehensive reports with AI insights

---

### AI-Enhanced XSS Scanner

Specialized XSS scanner with JavaScript analysis:

```bash
# Basic AI-enhanced XSS scan
python scanners/xss_scanner_ai.py -u https://example.com

# Custom output directory
python scanners/xss_scanner_ai.py -u https://example.com -o ./xss_results

# Disable AI features
python scanners/xss_scanner_ai.py -u https://example.com --no-ai
```

**AI Features:**
- Extracts and analyzes JavaScript code
- Detects DOM XSS with context awareness
- Generates context-specific payloads
- Identifies false positives in findings
- Provides exploitability scores

---

### AI Report Generator

Generate beautiful reports with AI-powered summaries:

```bash
# Generate report from scan results
python reports/ai_report_generator.py -i results/example.com_ai_comprehensive_report.json

# Custom output directory
python reports/ai_report_generator.py -i results/scan.json -o ./reports

# Disable AI (template-based reports only)
python reports/ai_report_generator.py -i results/scan.json --no-ai
```

**Generated Reports:**
- Markdown report with AI insights
- HTML report with beautiful styling
- Executive summary in natural language
- Prioritized recommendations

---

### AI Analyzer (Standalone)

Use the AI analyzer directly for custom analysis:

```python
from tools.ai_analyzer import OllamaAnalyzer

# Initialize analyzer
analyzer = OllamaAnalyzer()

# Analyze a vulnerability
vuln = {
    'type': 'XSS',
    'url': 'https://example.com',
    'parameter': 'search',
    'payload': '<script>alert(1)</script>',
    'severity': 'High'
}

result = analyzer.analyze_vulnerability(vuln)
print(result['ai_analysis'])

# Analyze JavaScript code
js_code = """
var search = location.search;
document.getElementById('output').innerHTML = search;
"""

analysis = analyzer.analyze_javascript_code(js_code, 'https://example.com/app.js')
print(analysis)

# Detect false positives
vulnerabilities = [vuln1, vuln2, vuln3]
filtered = analyzer.detect_false_positives(vulnerabilities)

# Generate executive summary
scan_results = {...}
summary = analyzer.generate_executive_summary(scan_results)
print(summary)

# Get AI-suggested payloads
context = {
    'url': 'https://example.com',
    'parameter': 'search',
    'technology': 'PHP',
    'input_context': 'URL parameter'
}
payloads = analyzer.suggest_payloads('XSS', context)
```

---

## 🎯 AI Analysis Examples

### Example 1: Vulnerability Analysis

**Input:**
```json
{
  "type": "DOM XSS",
  "url": "https://example.com/search",
  "parameter": "q",
  "payload": "<script>alert(1)</script>",
  "severity": "High"
}
```

**AI Output:**
```json
{
  "severity": "High",
  "exploitability_score": 8,
  "impact": "An attacker can execute arbitrary JavaScript in the victim's browser, potentially stealing session cookies, credentials, or performing actions on behalf of the user.",
  "remediation": "1. Use textContent instead of innerHTML\n2. Implement Content Security Policy (CSP)\n3. Sanitize user input with DOMPurify\n4. Encode output properly",
  "is_false_positive": false,
  "confidence": 95
}
```

---

### Example 2: False Positive Detection

**Input:**
```json
{
  "type": "Potential DOM XSS",
  "url": "https://example.com/page.js",
  "payload": "setTimeout with function reference",
  "evidence": "setTimeout(myFunction, 1000)"
}
```

**AI Output:**
```json
{
  "is_false_positive": true,
  "confidence": 95,
  "reason": "setTimeout is called with a function reference, not a string. This is safe usage and does not allow code injection. Only setTimeout with string arguments is dangerous."
}
```

---

### Example 3: JavaScript Analysis

**Input:**
```javascript
var userInput = location.hash.substring(1);
document.getElementById('output').innerHTML = userInput;
```

**AI Output:**
```json
{
  "vulnerabilities": [
    {
      "sink": "innerHTML",
      "source": "location.hash",
      "description": "User-controlled input from URL hash is directly assigned to innerHTML without sanitization",
      "code_snippet": "document.getElementById('output').innerHTML = userInput",
      "severity": "High"
    }
  ],
  "risk_level": "High",
  "recommendations": [
    "Use textContent instead of innerHTML for plain text",
    "Implement DOMPurify for HTML sanitization",
    "Validate and encode user input",
    "Consider using a framework with automatic XSS protection"
  ]
}
```

---

## 🔧 Configuration Options

### Environment Variables

```bash
# Required
OLLAMA_API_KEY=your_api_key_here

# Optional (with defaults)
OLLAMA_BASE_URL=https://api.ollama.cloud
OLLAMA_MODEL=llama3.1:8b
```

### Supported Models

- `llama3.1:8b` (default, recommended)
- `llama3.1:70b` (more accurate, slower)
- `llama3.2:3b` (faster, less accurate)
- `mistral:7b`
- Any other Ollama Cloud compatible model

### Custom Configuration

```python
from tools.ai_analyzer import OllamaAnalyzer

# Use custom model
analyzer = OllamaAnalyzer(
    api_key='your_key',
    base_url='https://api.ollama.cloud',
    model='llama3.1:70b'
)
```

---

## 📊 Understanding AI Output

### Severity Levels
- **Critical**: Immediate exploitation possible, severe impact
- **High**: Exploitation likely, significant impact
- **Medium**: Exploitation possible with conditions, moderate impact
- **Low**: Limited exploitability or impact

### Exploitability Score (1-10)
- **9-10**: Trivial to exploit, no special conditions
- **7-8**: Easy to exploit with basic knowledge
- **5-6**: Moderate difficulty, requires specific conditions
- **3-4**: Difficult to exploit, many conditions required
- **1-2**: Very difficult or theoretical

### False Positive Confidence
- **90-100%**: Very high confidence, likely false positive
- **70-89%**: High confidence, probably false positive
- **50-69%**: Moderate confidence, manual review recommended
- **Below 50%**: Low confidence, likely real vulnerability

---

## 🎓 Best Practices

### 1. Always Verify AI Findings
- AI analysis is a tool, not a replacement for manual verification
- Test exploitability manually before reporting
- Understand the vulnerability, don't just copy AI output

### 2. Use AI for Prioritization
- Focus on high exploitability scores first
- Review false positive warnings carefully
- Use AI recommendations as a starting point

### 3. Combine AI with Manual Analysis
- Use AI to filter noise and prioritize
- Apply your expertise to validate findings
- Leverage AI for initial triage, manual review for confirmation

### 4. Monitor API Usage
- AI analysis uses API credits
- Limit scans to authorized targets only
- Use `--no-ai` flag for quick scans without AI

### 5. Keep Your API Key Secure
- Never commit `.env` file to version control
- Use environment variables in production
- Rotate API keys regularly

---

## 🐛 Troubleshooting

### "Ollama API key not found"
**Solution:** Make sure you've created a `.env` file with `OLLAMA_API_KEY` set.

```bash
cp .env.example .env
# Edit .env and add your API key
```

### "AI analysis disabled"
**Causes:**
- Missing or invalid API key
- Network connectivity issues
- Ollama Cloud service unavailable

**Solution:** Check your API key, internet connection, and Ollama Cloud status.

### "Could not parse JSON"
**Cause:** AI response format issue (rare)

**Solution:** The tool will store the raw response. This doesn't affect other features.

### Slow Performance
**Solutions:**
- Use a faster model (e.g., `llama3.2:3b`)
- Reduce the number of findings to analyze
- Use `--no-ai` for quick scans

---

## 💡 Tips & Tricks

### Tip 1: Batch Processing
```bash
# Scan multiple targets
for target in target1.com target2.com target3.com; do
    python tools/ai_vulnerability_scanner.py -t $target -o results/$target
done
```

### Tip 2: Focus on Specific Vulnerability Types
```bash
# XSS only with AI
python scanners/xss_scanner_ai.py -u https://target.com

# Then generate report
python reports/ai_report_generator.py -i results/target.com_xss_ai_scan.json
```

### Tip 3: Progressive Scanning
```bash
# First, quick scan without AI
python tools/ai_vulnerability_scanner.py -t target.com --no-ai

# Then, apply AI analysis to results
python reports/ai_report_generator.py -i results/target.com_comprehensive_report.json
```

### Tip 4: Custom Payload Testing
```python
from tools.ai_analyzer import OllamaAnalyzer

analyzer = OllamaAnalyzer()

# Get custom payloads for specific context
context = {
    'url': 'https://target.com/search',
    'parameter': 'q',
    'technology': 'WordPress',
    'input_context': 'Search form with WAF'
}

payloads = analyzer.suggest_payloads('XSS', context)
# Test these payloads manually
```

---

## 📈 Performance Metrics

### Typical Scan Times (with AI)
- **Small site** (1-5 pages): 2-5 minutes
- **Medium site** (5-20 pages): 5-15 minutes
- **Large site** (20+ pages): 15-30 minutes

### AI Analysis Overhead
- **Per vulnerability**: ~2-5 seconds
- **JavaScript analysis**: ~3-10 seconds per script
- **Executive summary**: ~5-10 seconds
- **False positive detection**: ~1-3 seconds per finding

---

## 🤝 Contributing

Have ideas for AI features? Found a bug? Contributions welcome!

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

## 📄 License

For educational and authorized security testing only.

---

## 🙏 Acknowledgments

- **Ollama Cloud** for providing the AI infrastructure
- **OWASP** for security testing methodologies
- **Bug bounty community** for inspiration and feedback

---

**Happy Hunting! 🎯✨**

*Remember: Always get permission before testing, and use AI responsibly!*
