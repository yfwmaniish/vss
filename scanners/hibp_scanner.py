#!/usr/bin/env python3
"""
HMS - Have I Been Pwned Integration
Checks email or domain breaches using Have I Been Pwned API.
"""

import asyncio
import aiohttp
import json
import logging
import hashlib
import time
from typing import Dict, Any
from urllib.parse import quote

class HaveIBeenPwnedScanner:
    def __init__(self, api_key: str, timeout: int = 10):
        self.api_key = api_key
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.base_url = "https://haveibeenpwned.com/api/v3"

    async def check_email(self, email: str) -> Dict[str, Any]:
        """
        Check if an email has been breached
        """
        self.logger.info(f"Checking breaches for email: {email}")
        url = f"{self.base_url}/breachedaccount/{quote(email)}"

        headers = {
            'hibp-api-key': self.api_key,
            'User-Agent': 'HIBP-Client'
        }

        results = {
            'email': email,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'breaches': [],
            'findings': []
        }

        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        breaches = await response.json()
                        results['breaches'] = breaches
                        
                        for breach in breaches:
                            results['findings'].append({
                                'type': 'Email Breach',
                                'severity': 'HIGH',
                                'breach': breach['Name'],
                                'description': f"Email was part of the {breach['Name']} breach affecting {breach['PwnCount']} accounts"
                            })
                    elif response.status == 404:
                        results['findings'].append({
                            'type': 'No Breach',
                            'severity': 'INFO',
                            'description': 'No breaches found for this email'
                        })
                    else:
                        results['findings'].append({
                            'type': 'API Error',
                            'severity': 'LOW',
                            'description': f'HIBP API error: {response.status}'
                        })
        except Exception as e:
            self.logger.error(f"Error checking email breaches: {e}")
            results['findings'].append({
                'type': 'Breach Check Error',
                'severity': 'LOW',
                'description': f'Error checking email breaches: {str(e)}'
            })

        return results

    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """
        Check if a domain has been breached
        """
        self.logger.info(f"Checking breaches for domain: {domain}")
        url = f"{self.base_url}/breaches"  # No direct API for domain, should query all breaches

        headers = {
            'hibp-api-key': self.api_key,
            'User-Agent': 'HIBP-Client'
        }

        results = {
            'domain': domain,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'findings': []
        }

        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        breaches = await response.json()

                        for breach in breaches:
                            if domain.lower() in (breach.get('Domain') or '').lower():
                                results['findings'].append({
                                    'type': 'Domain Breach',
                                    'severity': 'HIGH',
                                    'breach': breach['Name'],
                                    'description': f"Domain was involved in the {breach['Name']} breach"
                                })
                    else:
                        results['findings'].append({
                            'type': 'API Error',
                            'severity': 'LOW',
                            'description': f'HIBP API error while checking domain: {response.status}'
                        })
        except Exception as e:
            self.logger.error(f"Error checking domain breaches: {e}")
            results['findings'].append({
                'type': 'Breach Check Error',
                'severity': 'LOW',
                'description': f'Error checking domain breaches: {str(e)}'
            })

        return results

# Example usage
if __name__ == "__main__":
    async def main():
        # Replace with your actual HIBP API key
        api_key = "your_hibp_api_key_here"
        scanner = HaveIBeenPwnedScanner(api_key)
        email_results = await scanner.check_email("example@example.com")
        print(json.dumps(email_results, indent=2, default=str))

        domain_results = await scanner.check_domain("example.com")
        print(json.dumps(domain_results, indent=2, default=str))

    asyncio.run(main())

