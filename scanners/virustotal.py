#!/usr/bin/env python3
"""
HMS - VirusTotal Integration
Checks URL/domain reputation using VirusTotal API.
"""

import asyncio
import aiohttp
import json
import logging
import time
import hashlib
import base64
from typing import Dict, Any, Optional
from urllib.parse import urlparse

class VirusTotalScanner:
    def __init__(self, api_key: str, timeout: int = 30):
        self.api_key = api_key
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.base_url = "https://www.virustotal.com/api/v3"
        
        # Rate limiting (4 requests per minute for free tier)
        self.rate_limit_delay = 15  # seconds between requests
        
    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Main scanning function for VirusTotal reputation check
        """
        self.logger.info(f"Starting VirusTotal scan for {target}")
        
        results = {
            'target': target,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'findings': [],
            'url_analysis': {},
            'domain_analysis': {},
            'ip_analysis': {}
        }
        
        if not self.api_key:
            results['findings'].append({
                'type': 'Configuration Error',
                'severity': 'LOW',
                'description': 'VirusTotal API key not provided'
            })
            return results
        
        try:
            # Parse target to get components
            parsed_url = urlparse(target if target.startswith(('http://', 'https://')) else f'http://{target}')
            domain = parsed_url.netloc or parsed_url.path
            
            # Scan URL
            if target.startswith(('http://', 'https://')):
                url_results = await self._scan_url(target)
                results['url_analysis'] = url_results
                if url_results.get('findings'):
                    results['findings'].extend(url_results['findings'])
            
            # Scan domain
            if domain:
                domain_results = await self._scan_domain(domain)
                results['domain_analysis'] = domain_results
                if domain_results.get('findings'):
                    results['findings'].extend(domain_results['findings'])
                
                # Get IP and scan it
                ip_address = domain_results.get('ip_address')
                if ip_address:
                    ip_results = await self._scan_ip(ip_address)
                    results['ip_analysis'] = ip_results
                    if ip_results.get('findings'):
                        results['findings'].extend(ip_results['findings'])
            
            self.logger.info(f"VirusTotal scan completed for {target}")
            
        except Exception as e:
            self.logger.error(f"Error during VirusTotal scan: {e}")
            results['findings'].append({
                'type': 'Scan Error',
                'severity': 'LOW',
                'description': f'Error during VirusTotal scan: {str(e)}'
            })
        
        return results
    
    async def _scan_url(self, url: str) -> Dict[str, Any]:
        """Scan URL using VirusTotal API"""
        results = {'findings': [], 'stats': {}, 'scan_date': None}
        
        try:
            # Create URL ID for VirusTotal
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            
            headers = {'X-Apikey': self.api_key}
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                # Get URL analysis
                async with session.get(f"{self.base_url}/urls/{url_id}", headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        attributes = data.get('data', {}).get('attributes', {})
                        
                        # Extract scan results
                        last_analysis_stats = attributes.get('last_analysis_stats', {})
                        results['stats'] = last_analysis_stats
                        results['scan_date'] = attributes.get('last_analysis_date')
                        
                        # Check for malicious detections
                        malicious_count = last_analysis_stats.get('malicious', 0)
                        suspicious_count = last_analysis_stats.get('suspicious', 0)
                        
                        if malicious_count > 0:
                            results['findings'].append({
                                'type': 'Malicious URL',
                                'severity': 'CRITICAL',
                                'description': f'URL flagged as malicious by {malicious_count} security vendors',
                                'malicious_count': malicious_count,
                                'total_scans': sum(last_analysis_stats.values())
                            })
                        
                        if suspicious_count > 0:
                            results['findings'].append({
                                'type': 'Suspicious URL',
                                'severity': 'HIGH',
                                'description': f'URL flagged as suspicious by {suspicious_count} security vendors',
                                'suspicious_count': suspicious_count,
                                'total_scans': sum(last_analysis_stats.values())
                            })
                        
                        # Extract detailed scan results
                        last_analysis_results = attributes.get('last_analysis_results', {})
                        results['detailed_results'] = {}
                        
                        for engine, result in last_analysis_results.items():
                            if result.get('category') in ['malicious', 'suspicious']:
                                results['detailed_results'][engine] = {
                                    'category': result.get('category'),
                                    'result': result.get('result'),
                                    'method': result.get('method')
                                }
                    
                    elif response.status == 404:
                        # URL not found, submit for analysis
                        await self._submit_url_for_analysis(session, url, headers)
                        results['findings'].append({
                            'type': 'URL Not Analyzed',
                            'severity': 'INFO',
                            'description': 'URL submitted to VirusTotal for analysis'
                        })
                    
                    else:
                        results['findings'].append({
                            'type': 'API Error',
                            'severity': 'LOW',
                            'description': f'VirusTotal API error: {response.status}'
                        })
            
            # Rate limiting
            await asyncio.sleep(self.rate_limit_delay)
            
        except Exception as e:
            self.logger.error(f"Error scanning URL: {e}")
            results['findings'].append({
                'type': 'URL Scan Error',
                'severity': 'LOW',
                'description': f'Error scanning URL: {str(e)}'
            })
        
        return results
    
    async def _scan_domain(self, domain: str) -> Dict[str, Any]:
        """Scan domain using VirusTotal API"""
        results = {'findings': [], 'stats': {}, 'ip_address': None, 'whois': {}}
        
        try:
            headers = {'X-Apikey': self.api_key}
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                # Get domain analysis
                async with session.get(f"{self.base_url}/domains/{domain}", headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        attributes = data.get('data', {}).get('attributes', {})
                        
                        # Extract scan results
                        last_analysis_stats = attributes.get('last_analysis_stats', {})
                        results['stats'] = last_analysis_stats
                        
                        # Get IP address
                        results['ip_address'] = attributes.get('last_dns_records', [{}])[0].get('value')
                        
                        # Get WHOIS data
                        results['whois'] = attributes.get('whois', '')
                        
                        # Check for malicious detections
                        malicious_count = last_analysis_stats.get('malicious', 0)
                        suspicious_count = last_analysis_stats.get('suspicious', 0)
                        
                        if malicious_count > 0:
                            results['findings'].append({
                                'type': 'Malicious Domain',
                                'severity': 'CRITICAL',
                                'description': f'Domain flagged as malicious by {malicious_count} security vendors',
                                'malicious_count': malicious_count,
                                'total_scans': sum(last_analysis_stats.values())
                            })
                        
                        if suspicious_count > 0:
                            results['findings'].append({
                                'type': 'Suspicious Domain',
                                'severity': 'HIGH',
                                'description': f'Domain flagged as suspicious by {suspicious_count} security vendors',
                                'suspicious_count': suspicious_count,
                                'total_scans': sum(last_analysis_stats.values())
                            })
                        
                        # Check domain reputation
                        reputation = attributes.get('reputation', 0)
                        if reputation < -50:
                            results['findings'].append({
                                'type': 'Poor Domain Reputation',
                                'severity': 'HIGH',
                                'description': f'Domain has poor reputation score: {reputation}',
                                'reputation': reputation
                            })
                        elif reputation < 0:
                            results['findings'].append({
                                'type': 'Negative Domain Reputation',
                                'severity': 'MEDIUM',
                                'description': f'Domain has negative reputation score: {reputation}',
                                'reputation': reputation
                            })
                    
                    else:
                        results['findings'].append({
                            'type': 'API Error',
                            'severity': 'LOW',
                            'description': f'VirusTotal API error for domain: {response.status}'
                        })
            
            # Rate limiting
            await asyncio.sleep(self.rate_limit_delay)
            
        except Exception as e:
            self.logger.error(f"Error scanning domain: {e}")
            results['findings'].append({
                'type': 'Domain Scan Error',
                'severity': 'LOW',
                'description': f'Error scanning domain: {str(e)}'
            })
        
        return results
    
    async def _scan_ip(self, ip_address: str) -> Dict[str, Any]:
        """Scan IP address using VirusTotal API"""
        results = {'findings': [], 'stats': {}, 'country': None, 'as_owner': None}
        
        try:
            headers = {'X-Apikey': self.api_key}
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                # Get IP analysis
                async with session.get(f"{self.base_url}/ip_addresses/{ip_address}", headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        attributes = data.get('data', {}).get('attributes', {})
                        
                        # Extract scan results
                        last_analysis_stats = attributes.get('last_analysis_stats', {})
                        results['stats'] = last_analysis_stats
                        
                        # Get geolocation info
                        results['country'] = attributes.get('country')
                        results['as_owner'] = attributes.get('as_owner')
                        
                        # Check for malicious detections
                        malicious_count = last_analysis_stats.get('malicious', 0)
                        suspicious_count = last_analysis_stats.get('suspicious', 0)
                        
                        if malicious_count > 0:
                            results['findings'].append({
                                'type': 'Malicious IP',
                                'severity': 'CRITICAL',
                                'description': f'IP address flagged as malicious by {malicious_count} security vendors',
                                'malicious_count': malicious_count,
                                'total_scans': sum(last_analysis_stats.values())
                            })
                        
                        if suspicious_count > 0:
                            results['findings'].append({
                                'type': 'Suspicious IP',
                                'severity': 'HIGH',
                                'description': f'IP address flagged as suspicious by {suspicious_count} security vendors',
                                'suspicious_count': suspicious_count,
                                'total_scans': sum(last_analysis_stats.values())
                            })
                        
                        # Check IP reputation
                        reputation = attributes.get('reputation', 0)
                        if reputation < -50:
                            results['findings'].append({
                                'type': 'Poor IP Reputation',
                                'severity': 'HIGH',
                                'description': f'IP address has poor reputation score: {reputation}',
                                'reputation': reputation
                            })
                    
                    else:
                        results['findings'].append({
                            'type': 'API Error',
                            'severity': 'LOW',
                            'description': f'VirusTotal API error for IP: {response.status}'
                        })
            
            # Rate limiting
            await asyncio.sleep(self.rate_limit_delay)
            
        except Exception as e:
            self.logger.error(f"Error scanning IP: {e}")
            results['findings'].append({
                'type': 'IP Scan Error',
                'severity': 'LOW',
                'description': f'Error scanning IP: {str(e)}'
            })
        
        return results
    
    async def _submit_url_for_analysis(self, session: aiohttp.ClientSession, url: str, headers: dict):
        """Submit URL to VirusTotal for analysis"""
        try:
            data = aiohttp.FormData()
            data.add_field('url', url)
            
            async with session.post(f"{self.base_url}/urls", headers=headers, data=data) as response:
                if response.status == 200:
                    self.logger.info(f"URL submitted for analysis: {url}")
                else:
                    self.logger.warning(f"Failed to submit URL for analysis: {response.status}")
        
        except Exception as e:
            self.logger.error(f"Error submitting URL for analysis: {e}")

# Example usage
if __name__ == "__main__":
    async def main():
        # Replace with your actual VirusTotal API key
        api_key = "your_virustotal_api_key_here"
        scanner = VirusTotalScanner(api_key)
        results = await scanner.scan("https://example.com")
        print(json.dumps(results, indent=2, default=str))
    
    asyncio.run(main())
