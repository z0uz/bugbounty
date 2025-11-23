# 🚀 Ollama Cloud Setup Guide

Quick guide to get started with Ollama Cloud AI features in your bug bounty toolkit.

## Prerequisites

- Python 3.7+
- Active Ollama Cloud account
- Internet connection

## Step-by-Step Setup

### 1. Get Your Ollama Cloud API Key

1. **Sign up or log in** to your Ollama Cloud account at [https://ollama.cloud](https://ollama.cloud)
2. Navigate to **API Keys** section in your dashboard
3. **Create a new API key** or copy your existing key
4. **Save it securely** - you'll need it in the next step

### 2. Install Dependencies

```bash
cd /home/zouz/Documents/coding/bug_bounty_toolkit
pip install -r requirements.txt
```

This will install:
- `ollama==0.3.3` - Ollama Python client
- All other required dependencies

### 3. Configure Your Environment

Create a `.env` file from the example:

```bash
cp .env.example .env
```

Edit `.env` and add your API key:

```bash
nano .env
# or use your preferred editor
```

Add your credentials:

```bash
# Ollama Cloud Configuration
OLLAMA_API_KEY=your_actual_api_key_here
OLLAMA_BASE_URL=https://api.ollama.cloud
OLLAMA_MODEL=llama3.1:8b
```

**Important:** Replace `your_actual_api_key_here` with your real API key!

### 4. Test Your Setup

Run the AI analyzer test:

```bash
python tools/ai_analyzer.py
```

You should see:
```
[AI] Initialized Ollama Cloud with model: llama3.1:8b
Test 1: Vulnerability Analysis
...
AI Analyzer tests complete!
```

If you see errors, check:
- API key is correct
- `.env` file is in the correct location
- Internet connection is working

### 5. Run Your First AI-Enhanced Scan

```bash
# Test with a safe target (your own site or authorized target)
python tools/ai_vulnerability_scanner.py -t example.com
```

## Configuration Options

### Choose Your Model

Different models offer different trade-offs:

| Model | Speed | Accuracy | Cost | Recommended For |
|-------|-------|----------|------|-----------------|
| `llama3.2:3b` | ⚡⚡⚡ | ⭐⭐ | 💰 | Quick scans, testing |
| `llama3.1:8b` | ⚡⚡ | ⭐⭐⭐ | 💰💰 | **Default, balanced** |
| `llama3.1:70b` | ⚡ | ⭐⭐⭐⭐ | 💰💰💰 | Critical findings, detailed analysis |
| `mistral:7b` | ⚡⚡ | ⭐⭐⭐ | 💰💰 | Alternative option |

To change model, edit `.env`:

```bash
OLLAMA_MODEL=llama3.1:70b
```

### Custom Base URL

If you're using a self-hosted Ollama instance:

```bash
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_API_KEY=  # Leave empty for local instance
```

## Verify Installation

### Quick Verification Checklist

- [ ] Python 3.7+ installed
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] `.env` file created with API key
- [ ] Test script runs successfully
- [ ] No error messages about missing API key

### Test Each Component

```bash
# Test AI analyzer
python tools/ai_analyzer.py

# Test AI-enhanced XSS scanner
python scanners/xss_scanner_ai.py -u https://example.com --no-ai
# (use --no-ai first to test without API calls)

# Test report generator
python reports/ai_report_generator.py --help
```

## Common Issues & Solutions

### Issue: "Ollama API key not found"

**Solution:**
```bash
# Check if .env file exists
ls -la .env

# Check if API key is set
cat .env | grep OLLAMA_API_KEY

# Make sure it's not the example value
# Should be: OLLAMA_API_KEY=sk-... (your actual key)
```

### Issue: "Module 'ollama' not found"

**Solution:**
```bash
pip install ollama==0.3.3
# or
pip install -r requirements.txt
```

### Issue: Connection errors

**Solutions:**
1. Check internet connection
2. Verify Ollama Cloud is accessible: `curl https://api.ollama.cloud`
3. Check if your API key is valid
4. Try with a different model

### Issue: Slow performance

**Solutions:**
1. Use a faster model: `OLLAMA_MODEL=llama3.2:3b`
2. Reduce scope of scan
3. Use `--no-ai` flag for quick scans
4. Check your internet speed

## Usage Examples

### Example 1: Full AI-Enhanced Scan

```bash
python tools/ai_vulnerability_scanner.py -t target.com -o ./results
```

### Example 2: XSS Scan with AI

```bash
python scanners/xss_scanner_ai.py -u https://target.com/search?q=test
```

### Example 3: Generate AI Report

```bash
# First, run a scan
python tools/ai_vulnerability_scanner.py -t target.com

# Then generate report from results
python reports/ai_report_generator.py -i results/target.com_ai_comprehensive_report.json
```

### Example 4: Disable AI (Traditional Scan)

```bash
python tools/ai_vulnerability_scanner.py -t target.com --no-ai
```

## Security Best Practices

### 🔒 Protect Your API Key

1. **Never commit `.env` to git**
   ```bash
   # .gitignore already includes .env
   git status  # Should not show .env
   ```

2. **Use environment variables in production**
   ```bash
   export OLLAMA_API_KEY="your_key"
   python tools/ai_vulnerability_scanner.py -t target.com
   ```

3. **Rotate keys regularly**
   - Generate new API key monthly
   - Revoke old keys after rotation

4. **Limit key permissions**
   - Use read-only keys if available
   - Create separate keys for different projects

### 🎯 Responsible Usage

1. **Only scan authorized targets**
   - Get written permission
   - Stay within scope
   - Follow bug bounty program rules

2. **Monitor API usage**
   - Check your Ollama Cloud dashboard
   - Set up usage alerts
   - Stay within your plan limits

3. **Validate AI findings**
   - Don't report based solely on AI analysis
   - Manually verify each vulnerability
   - Understand the exploit before reporting

## Next Steps

Now that you're set up:

1. **Read the full documentation**: `AI_FEATURES.md`
2. **Try example scans** on authorized targets
3. **Explore AI features** like false positive detection
4. **Generate beautiful reports** with AI insights
5. **Join the community** and share your findings

## Getting Help

- **Documentation**: See `AI_FEATURES.md` for detailed usage
- **Examples**: Check `examples/` directory
- **Issues**: Report bugs on GitHub
- **Community**: Join our Discord/Slack

## Useful Commands

```bash
# Check Python version
python --version

# List installed packages
pip list | grep ollama

# Test API connection
python -c "from tools.ai_analyzer import OllamaAnalyzer; OllamaAnalyzer()"

# View environment variables
cat .env

# Run with verbose output
python tools/ai_vulnerability_scanner.py -t target.com -v
```

---

**You're all set! Happy hunting with AI! 🎯✨**

*Remember: With great power comes great responsibility. Use AI ethically!*
