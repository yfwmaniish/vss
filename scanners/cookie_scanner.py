import aiohttp
import asyncio
import time
from urllib.parse import urlparse
from datetime import datetime, timedelta

class CookieSecurityScanner:
    def __init__(self, timeout=10):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.cookies_found = []
        self.vulnerabilities = []
        self.findings = []
        
    async def scan(self, target_url):
        """Main scan function to analyze cookie security"""
        if not target_url.startswith(('http://', 'https://')):
            target_url = f"http://{target_url}"
        
        # Parse URL to check if it's HTTPS
        parsed_url = urlparse(target_url)
        is_https = parsed_url.scheme == 'https'
        
        cookies_data = {
            'target': target_url,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'is_https': is_https,
            'cookies_found': [],
            'vulnerabilities': [],
            'findings': [],
            'stats': {
                'total_cookies': 0,
                'secure_cookies': 0,
                'httponly_cookies': 0,
                'samesite_cookies': 0,
                'vulnerable_cookies': 0
            }
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
        
        try:
            async with aiohttp.ClientSession(headers=headers, timeout=self.timeout) as session:
                # Get main page cookies
                await self._scan_url(session, target_url, cookies_data)
                
                # Also check common endpoints that might set cookies
                common_endpoints = [
                    '/login', '/auth', '/admin', '/dashboard', '/user',
                    '/account', '/profile', '/api/login', '/signin', '/session'
                ]
                
                for endpoint in common_endpoints:
                    endpoint_url = target_url.rstrip('/') + endpoint
                    await self._scan_url(session, endpoint_url, cookies_data, ignore_errors=True)
                
                # Analyze all found cookies
                self._analyze_cookies(cookies_data)
                
        except Exception as e:
            cookies_data['error'] = f"Error during cookie scan: {str(e)}"
            
        return cookies_data
    
    async def _scan_url(self, session, url, cookies_data, ignore_errors=False):
        """Scan a specific URL for cookies"""
        try:
            async with session.get(url, allow_redirects=True) as response:
                # Get cookies from Set-Cookie headers
                set_cookie_headers = response.headers.getall('Set-Cookie', [])
                
                for cookie_header in set_cookie_headers:
                    cookie_data = self._parse_cookie(cookie_header, url)
                    if cookie_data:
                        # Check if we already have this cookie (by name and url)
                        existing = any(c['name'] == cookie_data['name'] and c['url'] == cookie_data['url'] 
                                     for c in cookies_data['cookies_found'])
                        if not existing:
                            cookies_data['cookies_found'].append(cookie_data)
                        
        except Exception as e:
            if not ignore_errors:
                if 'errors' not in cookies_data:
                    cookies_data['errors'] = []
                cookies_data['errors'].append(f"Error scanning {url}: {str(e)}")
    
    def _parse_cookie(self, cookie_header, url):
        """Parse a Set-Cookie header and extract attributes"""
        parts = [part.strip() for part in cookie_header.split(';')]
        if not parts:
            return None
            
        # First part is name=value
        name_value = parts[0].split('=', 1)
        if len(name_value) != 2:
            return None
            
        cookie_name, cookie_value = name_value
        
        cookie_data = {
            'name': cookie_name.strip(),
            'value': cookie_value.strip(),
            'url': url,
            'raw_header': cookie_header,
            'secure': False,
            'httponly': False,
            'samesite': None,
            'path': '/',
            'domain': None,
            'expires': None,
            'max_age': None,
            'vulnerabilities': []
        }
        
        # Parse attributes
        for part in parts[1:]:
            attr = part.lower().strip()
            if '=' in attr:
                key, value = attr.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                if key == 'domain':
                    cookie_data['domain'] = value
                elif key == 'path':
                    cookie_data['path'] = value
                elif key == 'expires':
                    cookie_data['expires'] = value
                elif key == 'max-age':
                    cookie_data['max_age'] = value
                elif key == 'samesite':
                    cookie_data['samesite'] = value.capitalize()
            else:
                if attr == 'secure':
                    cookie_data['secure'] = True
                elif attr == 'httponly':
                    cookie_data['httponly'] = True
        
        return cookie_data
    
    def _analyze_cookies(self, cookies_data):
        """Analyze cookies for security vulnerabilities"""
        is_https = cookies_data['is_https']
        
        for cookie in cookies_data['cookies_found']:
            vulnerabilities = []
            
            # Check for missing Secure flag on HTTPS sites
            if is_https and not cookie['secure']:
                vulnerabilities.append({
                    'type': 'Missing Secure Flag',
                    'severity': 'MEDIUM',
                    'description': f"Cookie '{cookie['name']}' lacks Secure flag on HTTPS site"
                })
            
            # Check for missing HttpOnly flag
            if not cookie['httponly']:
                vulnerabilities.append({
                    'type': 'Missing HttpOnly Flag',
                    'severity': 'MEDIUM',
                    'description': f"Cookie '{cookie['name']}' lacks HttpOnly flag, vulnerable to XSS"
                })
            
            # Check for missing or weak SameSite attribute
            if not cookie['samesite'] or cookie['samesite'] == 'None':
                vulnerabilities.append({
                    'type': 'Missing/Weak SameSite',
                    'severity': 'HIGH',
                    'description': f"Cookie '{cookie['name']}' lacks proper SameSite protection, vulnerable to CSRF"
                })
            
            # Check for overly broad domain
            if cookie['domain'] and cookie['domain'].startswith('.'):
                vulnerabilities.append({
                    'type': 'Broad Domain Scope',
                    'severity': 'LOW',
                    'description': f"Cookie '{cookie['name']}' has broad domain scope: {cookie['domain']}"
                })
            
            # Check for sensitive data in cookie names or values
            sensitive_patterns = ['password', 'token', 'secret', 'key', 'auth', 'session', 'admin']
            cookie_text = (cookie['name'] + cookie['value']).lower()
            
            for pattern in sensitive_patterns:
                if pattern in cookie_text:
                    vulnerabilities.append({
                        'type': 'Potentially Sensitive Data',
                        'severity': 'MEDIUM',
                        'description': f"Cookie '{cookie['name']}' may contain sensitive data"
                    })
                    break
            
            # Check for long-lived cookies (no expiration)
            if not cookie['expires'] and not cookie['max_age']:
                vulnerabilities.append({
                    'type': 'Session Cookie Without Expiration',
                    'severity': 'LOW',
                    'description': f"Cookie '{cookie['name']}' is a session cookie without explicit expiration"
                })
            
            cookie['vulnerabilities'] = vulnerabilities
            cookies_data['vulnerabilities'].extend(vulnerabilities)
        
        # Generate findings for the report
        self._generate_findings(cookies_data)
        
        # Update statistics
        self._update_stats(cookies_data)
    
    def _generate_findings(self, cookies_data):
        """Generate findings for the report"""
        findings = []
        
        for cookie in cookies_data['cookies_found']:
            for vuln in cookie['vulnerabilities']:
                findings.append({
                    'type': vuln['type'],
                    'severity': vuln['severity'],
                    'description': vuln['description'],
                    'cookie_name': cookie['name'],
                    'url': cookie['url']
                })
        
        cookies_data['findings'] = findings
    
    def _update_stats(self, cookies_data):
        """Update statistics"""
        stats = cookies_data['stats']
        stats['total_cookies'] = len(cookies_data['cookies_found'])
        
        for cookie in cookies_data['cookies_found']:
            if cookie['secure']:
                stats['secure_cookies'] += 1
            if cookie['httponly']:
                stats['httponly_cookies'] += 1
            if cookie['samesite'] and cookie['samesite'] != 'None':
                stats['samesite_cookies'] += 1
            if cookie['vulnerabilities']:
                stats['vulnerable_cookies'] += 1
