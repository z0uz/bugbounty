#!/usr/bin/env python3
"""
Twitter Hacking Bot - Automated Cybersecurity Tweet Generator
Uses Ollama to generate informative hacking/security tweets and posts them to Twitter
"""

import os
import sys
import time
import random
import schedule
import tweepy
from datetime import datetime
from colorama import Fore, Style, init
from dotenv import load_dotenv
import ollama

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

init(autoreset=True)
load_dotenv()


class TwitterHackingBot:
    def __init__(self):
        """Initialize Twitter bot with API credentials and Ollama"""
        self.setup_twitter_api()
        self.setup_ollama()
        self.tweet_count = 0
        self.daily_limit = 5
        
        # Cybersecurity topics for tweet generation
        self.topics = [
            "XSS vulnerabilities",
            "SQL injection techniques",
            "CSRF protection",
            "API security",
            "SSRF attacks",
            "Authentication bypass",
            "IDOR vulnerabilities",
            "XXE injection",
            "Command injection",
            "Path traversal",
            "Race conditions",
            "Business logic flaws",
            "JWT security",
            "CORS misconfigurations",
            "Subdomain takeover",
            "Open redirect vulnerabilities",
            "File upload vulnerabilities",
            "Clickjacking",
            "Security headers",
            "Bug bounty tips",
            "Reconnaissance techniques",
            "Web application firewalls",
            "Rate limiting bypass",
            "OAuth vulnerabilities",
            "GraphQL security"
        ]
        
        # Popular hashtags for cybersecurity
        self.hashtags = [
            "#bugbounty", "#infosec", "#cybersecurity", "#hacking",
            "#ethicalhacking", "#appsec", "#websecurity", "#pentesting",
            "#bugbountytips", "#security", "#hackerone", "#bugcrowd",
            "#vulnerability", "#OWASP", "#redteam"
        ]
    
    def setup_twitter_api(self):
        """Setup Twitter API v2 authentication"""
        try:
            # Twitter API v2 credentials
            api_key = os.getenv('TWITTER_API_KEY')
            api_secret = os.getenv('TWITTER_API_SECRET')
            access_token = os.getenv('TWITTER_ACCESS_TOKEN')
            access_token_secret = os.getenv('TWITTER_ACCESS_TOKEN_SECRET')
            bearer_token = os.getenv('TWITTER_BEARER_TOKEN')
            
            if not all([api_key, api_secret, access_token, access_token_secret]):
                raise ValueError("Missing Twitter API credentials in .env file")
            
            # Create Twitter API v2 client
            self.twitter_client = tweepy.Client(
                bearer_token=bearer_token,
                consumer_key=api_key,
                consumer_secret=api_secret,
                access_token=access_token,
                access_token_secret=access_token_secret
            )
            
            print(f"{Fore.GREEN}[+] Twitter API connected successfully{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Twitter API setup failed: {str(e)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Please add Twitter API credentials to .env file{Style.RESET_ALL}")
            sys.exit(1)
    
    def setup_ollama(self):
        """Setup Ollama connection"""
        try:
            self.ollama_model = os.getenv('OLLAMA_MODEL', 'qwen3-coder:480b-cloud')
            
            # Test Ollama connection
            response = ollama.chat(
                model=self.ollama_model,
                messages=[{'role': 'user', 'content': 'test'}]
            )
            
            print(f"{Fore.GREEN}[+] Ollama connected successfully (Model: {self.ollama_model}){Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Ollama setup failed: {str(e)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Make sure Ollama is running and OLLAMA_API_KEY is set{Style.RESET_ALL}")
            sys.exit(1)
    
    def generate_tweet(self, topic: str) -> str:
        """Generate a short, informative hacking tweet using Ollama"""
        
        prompt = f"""Generate a short, informative cybersecurity tweet about {topic}.

Requirements:
- Maximum 200 characters (to leave room for hashtags)
- Educational and professional tone
- Include a practical tip or insight
- No hashtags (will be added separately)
- Focus on actionable information
- Suitable for bug bounty hunters and security researchers

Generate ONLY the tweet text, nothing else."""

        try:
            response = ollama.chat(
                model=self.ollama_model,
                messages=[
                    {
                        'role': 'system',
                        'content': 'You are a cybersecurity expert who writes concise, informative tweets about hacking and bug bounties.'
                    },
                    {
                        'role': 'user',
                        'content': prompt
                    }
                ]
            )
            
            tweet_text = response['message']['content'].strip()
            
            # Clean up the tweet
            tweet_text = tweet_text.replace('"', '').replace("'", "'")
            tweet_text = tweet_text.split('\n')[0]  # Take first line only
            
            # Ensure it's not too long
            if len(tweet_text) > 200:
                tweet_text = tweet_text[:197] + "..."
            
            return tweet_text
            
        except Exception as e:
            print(f"{Fore.RED}[-] Tweet generation failed: {str(e)}{Style.RESET_ALL}")
            return None
    
    def add_hashtags(self, tweet_text: str, num_hashtags: int = 3) -> str:
        """Add relevant hashtags to the tweet"""
        selected_hashtags = random.sample(self.hashtags, min(num_hashtags, len(self.hashtags)))
        hashtag_string = " ".join(selected_hashtags)
        
        # Ensure total length doesn't exceed 280 characters
        full_tweet = f"{tweet_text}\n\n{hashtag_string}"
        
        if len(full_tweet) > 280:
            # Reduce hashtags if needed
            while len(full_tweet) > 280 and num_hashtags > 1:
                num_hashtags -= 1
                selected_hashtags = random.sample(self.hashtags, num_hashtags)
                hashtag_string = " ".join(selected_hashtags)
                full_tweet = f"{tweet_text}\n\n{hashtag_string}"
        
        return full_tweet
    
    def post_tweet(self, tweet_text: str) -> bool:
        """Post tweet to Twitter"""
        try:
            response = self.twitter_client.create_tweet(text=tweet_text)
            print(f"{Fore.GREEN}[+] Tweet posted successfully!{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Tweet: {tweet_text}{Style.RESET_ALL}\n")
            return True
            
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to post tweet: {str(e)}{Style.RESET_ALL}")
            return False
    
    def generate_and_post_tweet(self):
        """Generate and post a single tweet"""
        if self.tweet_count >= self.daily_limit:
            print(f"{Fore.YELLOW}[!] Daily limit reached ({self.daily_limit} tweets){Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Generating Tweet #{self.tweet_count + 1}/{self.daily_limit}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        # Select random topic
        topic = random.choice(self.topics)
        print(f"{Fore.YELLOW}[*] Topic: {topic}{Style.RESET_ALL}")
        
        # Generate tweet
        print(f"{Fore.YELLOW}[*] Generating tweet with Ollama...{Style.RESET_ALL}")
        tweet_text = self.generate_tweet(topic)
        
        if not tweet_text:
            print(f"{Fore.RED}[-] Failed to generate tweet{Style.RESET_ALL}")
            return
        
        # Add hashtags
        full_tweet = self.add_hashtags(tweet_text)
        
        # Post tweet
        print(f"{Fore.YELLOW}[*] Posting to Twitter...{Style.RESET_ALL}")
        if self.post_tweet(full_tweet):
            self.tweet_count += 1
    
    def reset_daily_counter(self):
        """Reset daily tweet counter"""
        self.tweet_count = 0
        print(f"{Fore.GREEN}[+] Daily counter reset{Style.RESET_ALL}")
    
    def run_scheduled(self):
        """Run bot with scheduled tweets (5 per day)"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Twitter Hacking Bot - Scheduled Mode{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        print(f"{Fore.GREEN}[+] Bot started - Will post {self.daily_limit} tweets per day{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Schedule: Every ~3 hours during active hours (8 AM - 11 PM){Style.RESET_ALL}\n")
        
        # Schedule tweets throughout the day
        schedule.every().day.at("08:00").do(self.generate_and_post_tweet)
        schedule.every().day.at("11:00").do(self.generate_and_post_tweet)
        schedule.every().day.at("14:00").do(self.generate_and_post_tweet)
        schedule.every().day.at("17:00").do(self.generate_and_post_tweet)
        schedule.every().day.at("20:00").do(self.generate_and_post_tweet)
        
        # Reset counter at midnight
        schedule.every().day.at("00:00").do(self.reset_daily_counter)
        
        print(f"{Fore.GREEN}[+] Scheduled times: 08:00, 11:00, 14:00, 17:00, 20:00{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Bot is running... Press Ctrl+C to stop{Style.RESET_ALL}\n")
        
        try:
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Bot stopped by user{Style.RESET_ALL}")
    
    def run_immediate(self, count: int = 1):
        """Post tweets immediately (for testing)"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Twitter Hacking Bot - Immediate Mode{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        print(f"{Fore.GREEN}[+] Posting {count} tweet(s) immediately{Style.RESET_ALL}\n")
        
        for i in range(count):
            self.generate_and_post_tweet()
            
            if i < count - 1:
                # Wait between tweets to avoid rate limiting
                wait_time = random.randint(30, 60)
                print(f"{Fore.YELLOW}[*] Waiting {wait_time} seconds before next tweet...{Style.RESET_ALL}\n")
                time.sleep(wait_time)
        
        print(f"\n{Fore.GREEN}[+] All tweets posted!{Style.RESET_ALL}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Twitter Hacking Bot - Automated Cybersecurity Tweet Generator",
        epilog="Example: python twitter_hacking_bot.py --schedule"
    )
    parser.add_argument(
        "--schedule",
        action="store_true",
        help="Run in scheduled mode (5 tweets per day)"
    )
    parser.add_argument(
        "--immediate",
        type=int,
        metavar="COUNT",
        help="Post COUNT tweets immediately (for testing)"
    )
    
    args = parser.parse_args()
    
    bot = TwitterHackingBot()
    
    if args.schedule:
        bot.run_scheduled()
    elif args.immediate:
        bot.run_immediate(args.immediate)
    else:
        # Default: post one tweet
        bot.run_immediate(1)


if __name__ == "__main__":
    main()
