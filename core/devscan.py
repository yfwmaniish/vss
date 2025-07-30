"""
Dev/Debug Endpoint Scanner Module
Scans for exposed development/debug endpoints
"""

import requests
import asyncio
import aiohttp
import re
import json
from urllib.parse import urljoin, urlparse
import config


class DevEndpointScanner:
    def __init__(self, logger, timeout=10, threads=10, wordlist_path=None):
        self.logger = logger
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.DEFAULT_USER_AGENT})
        self.wordlist_path = wordlist_path

    async def scan_target(self, target):
        """Scan target for dev/debug endpoints"""
        results = {
            'target': target,
            'timestamp': self.logger.get_timestamp(),
            'endpoints_found': [],
            'pass': True,
            'findings': []
        }

        self.logger.info(f"Scanning target for development/debug endpoints: {target}")

        endpoints_to_scan = config.DEFAULT_DEV_ENDPOINTS
        
        # If custom wordlist provided, load from file
        if self.wordlist_path:
            self.logger.info(f"Loading endpoints from custom wordlist: {self.wordlist_path}")
            try:
                with open(self.wordlist_path, 'r') as f:
                    endpoints_to_scan = [line.strip() for line in f]
            except Exception as e:
                self.logger.error(f"Error loading custom wordlist: {e}")
                endpoints_to_scan = config.DEFAULT_DEV_ENDPOINTS  # fallback to default

        self.logger.info(f"Testing {len(endpoints_to_scan)} endpoints...")

        # Scan using asyncio for efficiency
        tasks = [self._scan_endpoint(target, endpoint) for endpoint in endpoints_to_scan]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for response_data in responses:
            if isinstance(response_data, dict):
                results['endpoints_found'].append(response_data)
                results['pass'] = False
                results['findings'].append({
                    'type': 'Exposed Dev/Debug Endpoint',
                    'severity': 'MEDIUM',
                    'endpoint': response_data['url'],
                    'details': response_data
                })

        return results

    async def _scan_endpoint(self, target, endpoint_path):
        """Scan a specific dev/debug endpoint"""
        # Ensure target has a scheme
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'
        
        url = f'{target.rstrip("/")}/{endpoint_path.lstrip("/")}'
        self.logger.info(f"Testing endpoint: {url}")

        try:
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                        if response.status == 200:
                            self.logger.success(f"Exposed endpoint found: {url}")

                            # Check for common indicators in response
                            response_text = await response.text()
                            response_indicators = []

                            if 'admin' in response_text.lower():
                                response_indicators.append('Admin panel reference')
                            if 'debug' in response_text.lower():
                                response_indicators.append('Debug information found')
                            if 'swagger' in response_text.lower():
                                response_indicators.append('Swagger docs available')
                            if 'phpinfo' in response_text.lower():
                                response_indicators.append('PHP info exposed')

                            return {
                                'url': url,
                                'status_code': response.status,
                                'content_length': response.content_length or len(response_text),
                                'indicators': response_indicators
                            }
                except asyncio.TimeoutError:
                    self.logger.info(f"Timeout scanning {url}")
                except Exception as e:
                    self.logger.info(f"Error scanning {url}: {e}")
        except Exception as e:
            self.logger.info(f"Error creating session for {url}: {e}")

        return None
    
    def _generate_custom_endpoints(self, base_paths):
        """Generate additional custom endpoints from base paths"""
        patterns = ['debug', 'api', 'swagger', 'admin', 'api-docs']
        generated = []
        for base in base_paths:
            for pattern in patterns:
                generated.append(f"{base}/{pattern}")
                generated.append(f"{base}/{pattern}/v1")
                generated.append(f"{base}/{pattern}/v2")
                generated.append(f"v1/{base}/{pattern}")
                generated.append(f"v2/{base}/{pattern}")
        return generated
    
    def _recursive_scan_mode(self, base_url, depth=1):
        """Scan recursively to a specified depth"""
        visited = set()
        
        def _recursive_scan(url, current_depth):
            if current_depth > depth or url in visited:
                return
            
            visited.add(url)
            self.logger.info(f"Recursive scan visiting: {url}")
            try:
                response = self.session.get(url, timeout=self.timeout)
            except requests.RequestException:
                return
            
            # Parse for new links to follow
            page_links = re.findall(r'href=[\'\"](.*?)[\'\"]', response.text)
            
            for link in page_links:
                full_url = urljoin(url, link)
                if full_url.startswith(base_url):
                    _recursive_scan(full_url, current_depth + 1)

        _recursive_scan(base_url, 0)
        return visited
    
    def _detect_framework(self, response_text):
        """Basic heuristic detection of web frameworks"""
        frameworks = {
            'Django': re.compile(r'Django|csrfmiddlewaretoken'),
            'Flask': re.compile(r'Flask|Werkzeug|Jinja2'),
            'Laravel': re.compile(r'Laravel|csrf_token'),
            'Express.js': re.compile(r'Express|req.params|res.json'),
            'ASP.NET': re.compile(r'ASP.NET|__VIEWSTATE')
        }
        detected = []
        for fw, pattern in frameworks.items():
            if pattern.search(response_text):
                detected.append(fw)
        return detected
