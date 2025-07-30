#!/usr/bin/env python3
"""
HMS - Subdomain Enumeration Scanner
Discovers subdomains using multiple techniques including DNS brute force,
certificate transparency logs, and search engines.
"""

import asyncio
import aiohttp
import dns.resolver
import socket
import ssl
import json
import logging
from urllib.parse import urlparse
from typing import List, Dict, Any, Set
import re
import time

class SubdomainScanner:
    def __init__(self, timeout: int = 10, max_concurrent: int = 50):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.logger = logging.getLogger(__name__)
        self.found_subdomains: Set[str] = set()
        
        # Common subdomain wordlist
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mx', 'email', 'imap',
            'pop3', 'ns3', 'owa', 'exchange', 'lync', 'lyncdiscover', 'sip', 'msoid',
            'portal', 'sharepoint', 'api', 'admin', 'test', 'dev', 'staging', 'prod',
            'blog', 'support', 'help', 'forum', 'shop', 'store', 'secure', 'vpn',
            'remote', 'cdn', 'static', 'img', 'images', 'video', 'videos', 'download',
            'files', 'docs', 'news', 'mobile', 'm', 'wap', 'demo', 'beta', 'old',
            'new', 'backup', 'bak', 'temp', 'tmp', 'archive', 'wiki', 'community',
            'git', 'svn', 'jenkins', 'jira', 'confluence', 'nagios', 'munin', 'zabbix'
        ]

    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Main scanning function that orchestrates all subdomain discovery techniques
        """
        domain = self._extract_domain(target)
        self.logger.info(f"Starting subdomain enumeration for {domain}")
        
        results = {
            'target': target,
            'domain': domain,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'findings': [],
            'subdomains': [],
            'stats': {
                'total_found': 0,
                'alive_subdomains': 0,
                'techniques_used': []
            }
        }
        
        try:
            # Run all discovery techniques concurrently
            techniques = await asyncio.gather(
                self._dns_bruteforce(domain),
                self._certificate_transparency(domain),
                self._search_engine_discovery(domain),
                self._dns_zone_transfer(domain),
                return_exceptions=True
            )
            
            # Process results from all techniques
            for i, technique_result in enumerate(techniques):
                if isinstance(technique_result, Exception):
                    self.logger.warning(f"Technique {i} failed: {technique_result}")
                    continue
                    
                if technique_result:
                    self.found_subdomains.update(technique_result)
            
            # Verify alive subdomains
            alive_subdomains = await self._verify_subdomains(list(self.found_subdomains))
            
            # Format results
            results['subdomains'] = sorted(list(self.found_subdomains))
            results['stats']['total_found'] = len(self.found_subdomains)
            results['stats']['alive_subdomains'] = len(alive_subdomains)
            results['stats']['techniques_used'] = ['dns_bruteforce', 'certificate_transparency', 'search_engines', 'zone_transfer']
            
            # Create findings for alive subdomains
            for subdomain in alive_subdomains:
                results['findings'].append({
                    'type': 'Subdomain Discovery',
                    'severity': 'INFO',
                    'description': f'Active subdomain discovered: {subdomain}',
                    'subdomain': subdomain,
                    'status': 'alive'
                })
            
            self.logger.info(f"Found {len(self.found_subdomains)} subdomains, {len(alive_subdomains)} alive")
            
        except Exception as e:
            self.logger.error(f"Error during subdomain enumeration: {e}")
            results['findings'].append({
                'type': 'Scan Error',
                'severity': 'LOW',
                'description': f'Error during subdomain enumeration: {str(e)}'
            })
        
        return results

    def _extract_domain(self, target: str) -> str:
        """Extract domain from URL or return as-is if already a domain"""
        if target.startswith(('http://', 'https://')):
            return urlparse(target).netloc
        return target

    async def _dns_bruteforce(self, domain: str) -> Set[str]:
        """Perform DNS brute force using common subdomain wordlist"""
        self.logger.info("Starting DNS brute force")
        found = set()
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def check_subdomain(subdomain):
            async with semaphore:
                full_domain = f"{subdomain}.{domain}"
                try:
                    # Use asyncio to run DNS resolution in thread pool
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, socket.gethostbyname, full_domain)
                    found.add(full_domain)
                    self.logger.debug(f"Found subdomain: {full_domain}")
                except (socket.gaierror, socket.herror):
                    pass  # Subdomain doesn't exist
                except Exception as e:
                    self.logger.debug(f"Error checking {full_domain}: {e}")
        
        # Create tasks for all subdomains
        tasks = [check_subdomain(sub) for sub in self.common_subdomains]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return found

    async def _certificate_transparency(self, domain: str) -> Set[str]:
        """Query certificate transparency logs for subdomains"""
        self.logger.info("Querying certificate transparency logs")
        found = set()
        
        ct_urls = [
            f"https://crt.sh/?q=%.{domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        ]
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            for url in ct_urls:
                try:
                    async with session.get(url) as response:
                        if response.status == 200:
                            if 'crt.sh' in url:
                                data = await response.json()
                                for cert in data:
                                    if 'name_value' in cert:
                                        names = cert['name_value'].split('\n')
                                        for name in names:
                                            name = name.strip()
                                            if name and domain in name and not name.startswith('*'):
                                                found.add(name)
                            
                            elif 'certspotter' in url:
                                data = await response.json()
                                for cert in data:
                                    if 'dns_names' in cert:
                                        for name in cert['dns_names']:
                                            if name and domain in name and not name.startswith('*'):
                                                found.add(name)
                                
                except Exception as e:
                    self.logger.debug(f"Error querying {url}: {e}")
        
        return found

    async def _search_engine_discovery(self, domain: str) -> Set[str]:
        """Use search engines to discover subdomains (limited without API keys)"""
        self.logger.info("Attempting search engine discovery")
        found = set()
        
        # This is a basic implementation - in practice, you'd use search engine APIs
        # For now, we'll just return empty set as most search engines block automated queries
        return found

    async def _dns_zone_transfer(self, domain: str) -> Set[str]:
        """Attempt DNS zone transfer (rarely works but worth trying)"""
        self.logger.info("Attempting DNS zone transfer")
        found = set()
        
        try:
            # Get NS records
            ns_records = dns.resolver.resolve(domain, 'NS')
            
            for ns in ns_records:
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                    for name in zone.nodes.keys():
                        subdomain = f"{name}.{domain}"
                        if subdomain != domain:
                            found.add(subdomain)
                except Exception as e:
                    self.logger.debug(f"Zone transfer failed for {ns}: {e}")
                    
        except Exception as e:
            self.logger.debug(f"Error getting NS records: {e}")
        
        return found

    async def _verify_subdomains(self, subdomains: List[str]) -> List[str]:
        """Verify which subdomains are actually alive"""
        self.logger.info(f"Verifying {len(subdomains)} subdomains")
        alive = []
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def check_alive(subdomain):
            async with semaphore:
                try:
                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=5),
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        for scheme in ['https', 'http']:
                            try:
                                url = f"{scheme}://{subdomain}"
                                async with session.get(url) as response:
                                    if response.status < 500:  # Any response except server errors
                                        alive.append(subdomain)
                                        return
                            except:
                                continue
                except Exception as e:
                    self.logger.debug(f"Error verifying {subdomain}: {e}")
        
        # Create tasks for all subdomains
        tasks = [check_alive(sub) for sub in subdomains]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return alive

# Example usage
if __name__ == "__main__":
    async def main():
        scanner = SubdomainScanner()
        results = await scanner.scan("example.com")
        print(json.dumps(results, indent=2))
    
    asyncio.run(main())
