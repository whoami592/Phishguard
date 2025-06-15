import re
import requests
from urllib.parse import urlparse
import email
import sys

def print_banner():
    banner = """
    ╔════════════════════════════════════════════════════╗
    ║                                                    ║
    ║          PhishGuard Tools - Anti-Phishing Suite     ║
    ║                                                    ║
    ║        Coded by Pakistani Ethical Hacker            ║
    ║            Mr. Sabaz Ali Khan                      ║
    ║                                                    ║
    ╚════════════════════════════════════════════════════╝
    """
    print(banner)

def check_url(url):
    try:
        # Basic URL validation
        if not url.startswith(('http://', 'https://')):
            return "Invalid URL: Must start with http:// or https://"
        
        # Parse URL components
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Check for suspicious characters
        suspicious_chars = ['@', '%', '#', ' ']
        if any(char in url for char in suspicious_chars):
            return "Warning: URL contains suspicious characters!"
        
        # Check domain reputation (basic check)
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return f"Warning: URL returned status code {response.status_code}"
        
        # Check for HTTPS
        if not url.startswith('https://'):
            return "Warning: URL is not using HTTPS!"
        
        return "URL appears safe (basic check passed)"
    except requests.RequestException:
        return "Error: Unable to connect to URL"

def analyze_email_headers(email_content):
    try:
        # Parse email content
        msg = email.message_from_string(email_content)
        
        # Check for common phishing indicators
        suspicious_indicators = []
        
        # Check From header
        from_header = msg.get('From', '')
        if not from_header or '@' not in from_header:
            suspicious_indicators.append("Missing or invalid From header")
        
        # Check Return-Path
        return_path = msg.get('Return-Path', '')
        if return_path and from_header and return_path != from_header:
            suspicious_indicators.append("Mismatched Return-Path and From headers")
        
        # Check for suspicious links in body
        if 'http://' in email_content and 'https://' not in email_content:
            suspicious_indicators.append("Contains non-secure HTTP links")
        
        if suspicious_indicators:
            return "Suspicious email detected:\n" + "\n".join(suspicious_indicators)
        return "Email headers appear normal (basic check)"
    except Exception as e:
        return f"Error analyzing email: {str(e)}"

def main():
    print_banner()
    print("1. URL Checker")
    print("2. Email Header Analyzer")
    print("3. Exit")
    
    while True:
        choice = input("\nEnter your choice (1-3): ")
        
        if choice == '1':
            url = input("Enter URL to check: ")
            result = check_url(url)
            print(f"\nResult: {result}\n")
        
        elif choice == '2':
            print("\nPaste email content (including headers) and press Enter twice:")
            lines = []
            while True:
                line = input()
                if line == "":
                    break
                lines.append(line)
            email_content = "\n".join(lines)
            result = analyze_email_headers(email_content)
            print(f"\nResult: {result}\n")
        
        elif choice == '3':
            print("Exiting PhishGuard Tools...")
            break
        
        else:
            print("Invalid choice! Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()