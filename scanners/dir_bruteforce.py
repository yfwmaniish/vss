import aiohttp
import asyncio
from pathlib import Path
import time
from urllib.parse import urljoin, urlparse

class DirBruteForcer:
    def __init__(self, base_url, wordlist_path, timeout=5, threads=10):
        self.base_url = base_url.rstrip('/')
        self.wordlist_path = wordlist_path
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.semaphore = asyncio.Semaphore(threads)
        self.found_paths = []
        self.start_time = None
        self.total_requests = 0
        
        # Common response codes to check
        self.interesting_codes = [200, 301, 302, 403, 401, 500]
        
    async def fetch(self, session, path):
        """Fetch a single path and return result info"""
        url = urljoin(self.base_url + '/', path)
        try:
            async with self.semaphore:
                async with session.get(url, timeout=self.timeout, allow_redirects=False) as response:
                    self.total_requests += 1
                    
                    if response.status in self.interesting_codes:
                        content_length = response.headers.get('content-length', 'Unknown')
                        content_type = response.headers.get('content-type', 'Unknown')
                        
                        return {
                            'url': url,
                            'path': path,
                            'status': response.status,
                            'content_length': content_length,
                            'content_type': content_type,
                            'server': response.headers.get('server', 'Unknown')
                        }
        except asyncio.TimeoutError:
            return None
        except Exception as e:
            # Silently ignore connection errors, DNS failures, etc.
            return None
            
        return None

    async def run(self):
        """Run the directory brute force scan"""
        self.start_time = time.time()
        
        # Check if wordlist exists
        if not Path(self.wordlist_path).exists():
            return {
                'error': f'Wordlist not found: {self.wordlist_path}',
                'found_paths': [],
                'total_found': 0,
                'scan_time': 0,
                'total_requests': 0
            }
        
        # Custom headers to appear more legitimate
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        async with aiohttp.ClientSession(headers=headers, connector=aiohttp.TCPConnector(limit=100)) as session:
            tasks = []
            paths_tested = []
            
            try:
                with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
                    for line_num, line in enumerate(file, 1):
                        path = line.strip()
                        if path and not path.startswith('#'):  # Skip empty lines and comments
                            paths_tested.append(path)
                            task = asyncio.create_task(self.fetch(session, path))
                            tasks.append(task)
                            
                            # Limit batch size to prevent memory issues
                            if len(tasks) >= 1000:
                                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                                for result in batch_results:
                                    if result and isinstance(result, dict):
                                        self.found_paths.append(result)
                                tasks = []
                
                # Process remaining tasks
                if tasks:
                    batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                    for result in batch_results:
                        if result and isinstance(result, dict):
                            self.found_paths.append(result)
                            
            except Exception as e:
                return {
                    'error': f'Error reading wordlist: {str(e)}',
                    'found_paths': [],
                    'total_found': 0,
                    'scan_time': time.time() - self.start_time,
                    'total_requests': self.total_requests
                }
        
        scan_time = time.time() - self.start_time
        
        # Sort results by status code, then by path
        self.found_paths.sort(key=lambda x: (x['status'], x['path']))
        
        return {
            'found_paths': self.found_paths,
            'total_found': len(self.found_paths),
            'scan_time': round(scan_time, 2),
            'total_requests': self.total_requests,
            'paths_tested': len(paths_tested),
            'wordlist_used': self.wordlist_path,
            'target_url': self.base_url,
            'requests_per_second': round(self.total_requests / scan_time, 2) if scan_time > 0 else 0
        }
