# Twitter Hacking Bot Setup Guide

## Overview

The Twitter Hacking Bot uses **Ollama** to generate short, informative cybersecurity tweets and automatically posts them to Twitter. It can post up to 5 tweets per day on topics like bug bounties, web security, and ethical hacking.

## Features

- ✨ **AI-Powered Tweet Generation**: Uses Ollama to create educational cybersecurity content
- 🤖 **Automated Scheduling**: Posts 5 tweets per day at optimal times
- 🎯 **Targeted Topics**: Covers 25+ cybersecurity topics including XSS, SQLi, API security, etc.
- #️⃣ **Smart Hashtags**: Automatically adds relevant hashtags (#bugbounty, #infosec, etc.)
- 📊 **Professional Tone**: Educational content suitable for security professionals
- ⏰ **Flexible Modes**: Scheduled or immediate posting

## Prerequisites

1. **Ollama Setup** (Already configured in your project)
   - Your Ollama API key is already set in `.env`
   - Model: `qwen3-coder:480b-cloud`

2. **Twitter Developer Account**
   - You need to create a Twitter Developer account
   - Apply for API access (Free tier is sufficient)

## Step 1: Get Twitter API Credentials

### 1.1 Create Twitter Developer Account

1. Go to [Twitter Developer Portal](https://developer.twitter.com/en/portal/dashboard)
2. Sign in with your Twitter account
3. Click "Sign up for Free Account"
4. Fill out the application form:
   - **Use case**: Select "Making a bot"
   - **Description**: "Automated bot for posting educational cybersecurity content"
5. Accept the terms and submit

### 1.2 Create a Twitter App

1. Once approved, go to the [Developer Portal](https://developer.twitter.com/en/portal/dashboard)
2. Click "Create Project" or "Create App"
3. Fill in the details:
   - **App name**: Choose a unique name (e.g., "CyberSecBot")
   - **Description**: "Educational cybersecurity tweet bot"
4. Click "Create"

### 1.3 Get API Keys

1. In your app settings, go to "Keys and tokens" tab
2. Generate/Copy the following:
   - **API Key** (Consumer Key)
   - **API Secret Key** (Consumer Secret)
   - **Bearer Token**
   - **Access Token** (Click "Generate" if not available)
   - **Access Token Secret**

3. **Important**: Save these keys securely - you won't be able to see them again!

### 1.4 Set Permissions

1. Go to "Settings" tab in your app
2. Scroll to "App permissions"
3. Click "Edit"
4. Select **"Read and Write"** (required for posting tweets)
5. Save changes

## Step 2: Configure the Bot

### 2.1 Update `.env` File

Open `/home/zouz/Documents/coding/bug_bounty_toolkit/.env` and add your Twitter credentials:

```bash
# Twitter API Configuration
TWITTER_API_KEY=your_actual_api_key_here
TWITTER_API_SECRET=your_actual_api_secret_here
TWITTER_ACCESS_TOKEN=your_actual_access_token_here
TWITTER_ACCESS_TOKEN_SECRET=your_actual_access_token_secret_here
TWITTER_BEARER_TOKEN=your_actual_bearer_token_here
```

**Replace** the placeholder values with your actual keys from Step 1.3.

### 2.2 Install Dependencies

```bash
cd /home/zouz/Documents/coding/bug_bounty_toolkit
pip install -r requirements.txt
```

This will install:
- `tweepy` - Twitter API library
- `schedule` - Task scheduling
- All other existing dependencies

## Step 3: Run the Bot

### Test Mode (Post 1 Tweet Immediately)

```bash
python tools/twitter_hacking_bot.py --immediate 1
```

This will:
- Generate 1 tweet using Ollama
- Add relevant hashtags
- Post it to Twitter immediately
- Great for testing!

### Post Multiple Tweets (Testing)

```bash
python tools/twitter_hacking_bot.py --immediate 3
```

Posts 3 tweets with 30-60 second delays between them.

### Scheduled Mode (5 Tweets Per Day)

```bash
python tools/twitter_hacking_bot.py --schedule
```

This will:
- Post tweets at: **8:00 AM, 11:00 AM, 2:00 PM, 5:00 PM, 8:00 PM**
- Automatically reset counter at midnight
- Run continuously (press Ctrl+C to stop)

### Run in Background (Linux/Mac)

```bash
# Using nohup
nohup python tools/twitter_hacking_bot.py --schedule > twitter_bot.log 2>&1 &

# Or using screen
screen -S twitter_bot
python tools/twitter_hacking_bot.py --schedule
# Press Ctrl+A then D to detach
```

## Tweet Topics

The bot covers 25+ cybersecurity topics:

- XSS vulnerabilities
- SQL injection techniques
- CSRF protection
- API security
- SSRF attacks
- Authentication bypass
- IDOR vulnerabilities
- XXE injection
- Command injection
- Path traversal
- Race conditions
- Business logic flaws
- JWT security
- CORS misconfigurations
- Subdomain takeover
- And more...

## Hashtags Used

The bot automatically adds 3 relevant hashtags from:

`#bugbounty` `#infosec` `#cybersecurity` `#hacking` `#ethicalhacking` `#appsec` `#websecurity` `#pentesting` `#bugbountytips` `#security` `#hackerone` `#bugcrowd` `#vulnerability` `#OWASP` `#redteam`

## Example Tweets

Here are examples of what the bot generates:

```
🔍 Pro tip: Always check for IDOR in API endpoints. 
Try incrementing/decrementing IDs in requests. 
Many apps fail to validate object ownership!

#bugbounty #appsec #ethicalhacking
```

```
⚠️ XSS in JSON responses? Check if Content-Type is 
application/json. Browsers won't execute JS if the 
header is set correctly. Always validate!

#websecurity #infosec #bugbountytips
```

## Troubleshooting

### Error: "Missing Twitter API credentials"

- Make sure you've added all 5 Twitter credentials to `.env`
- Check for typos in the credential names
- Ensure no extra spaces around the `=` sign

### Error: "403 Forbidden" when posting

- Check your app permissions (must be "Read and Write")
- Regenerate your Access Token after changing permissions
- Update the new tokens in `.env`

### Error: "429 Too Many Requests"

- You've hit Twitter's rate limit
- Wait 15 minutes before trying again
- Reduce posting frequency

### Error: "Ollama connection failed"

- Make sure Ollama is running
- Check `OLLAMA_API_KEY` in `.env`
- Verify the model name is correct

### Tweets are too long

- The bot automatically truncates tweets to fit Twitter's 280 character limit
- Hashtags are reduced if needed

## Rate Limits

**Twitter Free Tier Limits:**
- 1,500 tweets per month (~50 per day)
- Our bot posts 5 per day = 150 per month ✅
- Well within limits!

## Customization

### Change Tweet Schedule

Edit `tools/twitter_hacking_bot.py`, line ~230:

```python
schedule.every().day.at("08:00").do(self.generate_and_post_tweet)
schedule.every().day.at("11:00").do(self.generate_and_post_tweet)
# Add more times or change existing ones
```

### Change Daily Limit

Edit line ~35:

```python
self.daily_limit = 5  # Change to your desired number
```

### Add More Topics

Edit the `self.topics` list (line ~40) to add your own topics.

### Add More Hashtags

Edit the `self.hashtags` list (line ~70) to add custom hashtags.

## Security Best Practices

1. **Never commit `.env` to Git** - It contains sensitive API keys
2. **Use environment variables** in production
3. **Rotate API keys** periodically
4. **Monitor bot activity** regularly
5. **Follow Twitter's automation rules**

## Twitter Automation Rules

⚠️ **Important**: Follow Twitter's automation rules to avoid account suspension:

1. ✅ **DO**: Post original, valuable content
2. ✅ **DO**: Space out tweets (our bot does this)
3. ✅ **DO**: Stay within rate limits
4. ❌ **DON'T**: Post duplicate content
5. ❌ **DON'T**: Spam hashtags
6. ❌ **DON'T**: Post misleading information

Our bot is designed to follow these rules automatically.

## Support

If you encounter issues:

1. Check the logs for error messages
2. Verify all API credentials are correct
3. Ensure Ollama is running
4. Test with `--immediate 1` first
5. Check Twitter API status: https://api.twitterstat.us/

## Advanced Usage

### Custom Ollama Model

Change the model in `.env`:

```bash
OLLAMA_MODEL=llama2  # or any other model
```

### Integration with CI/CD

You can run the bot in a Docker container or as a cron job:

```bash
# Crontab example (run at specific times)
0 8,11,14,17,20 * * * cd /path/to/project && python tools/twitter_hacking_bot.py --immediate 1
```

## License

This bot is part of the Bug Bounty Toolkit and follows the same license.

## Disclaimer

This bot is for educational purposes. Always follow Twitter's Terms of Service and automation rules. The authors are not responsible for any account suspensions or violations.

---

**Happy Tweeting! 🐦🔐**
