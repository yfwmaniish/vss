"""
Shodan Lookup Module
Integrates with Shodan API for external reconnaissance
"""

import requests
import socket
import config


class ShodanScanner:
    def __init__(self, logger, api_key):
        self.logger = logger
        self.api_key = api_key
        self.base_url = "https://api.shodan.io"

    def lookup_target(self, target):
        """Lookup target information via Shodan API"""
        results = {
            'target': target,
            'timestamp': self.logger.get_timestamp(),
            'shodan_data': {},
            'pass': True,
            'findings': []
        }

        self.logger.info(f"Performing Shodan lookup for: {target}")

        # Resolve domain to IP if needed
        ip_address = self._resolve_target(target)
        if not ip_address:
            results['findings'].append({
                'type': 'Resolution Error',
                'severity': 'LOW',
                'description': f'Could not resolve target to IP address'
            })
            return results

        results['ip_address'] = ip_address

        # Perform Shodan host lookup
        host_data = self._shodan_host_lookup(ip_address)
        if host_data:
            results['shodan_data'] = host_data
            results['pass'] = False  # Found in Shodan means it's exposed

            # Analyze findings
            self._analyze_shodan_data(host_data, results)

        return results

    def _resolve_target(self, target):
        """Resolve target to IP address"""
        try:
            # If target is already an IP, return it
            socket.inet_aton(target)
            return target
        except socket.error:
            pass

        # Remove protocol if present
        if target.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            target = urlparse(target).netloc

        # Remove port if present
        if ':' in target and not target.count(':') > 1:  # Not IPv6
            target = target.split(':')[0]

        try:
            ip_address = socket.gethostbyname(target)
            self.logger.success(f"Resolved {target} to {ip_address}")
            return ip_address
        except socket.gaierror as e:
            self.logger.info(f"Failed to resolve {target}: {str(e)}")
            return None

    def _shodan_host_lookup(self, ip_address):
        """Perform Shodan API host lookup"""
        try:
            url = f"{self.base_url}/shodan/host/{ip_address}"
            params = {'key': self.api_key}
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                self.logger.success(f"Found Shodan data for {ip_address}")
                return data
            elif response.status_code == 404:
                self.logger.info(f"No Shodan data found for {ip_address}")
                return None
            elif response.status_code == 401:
                self.logger.warning("Invalid Shodan API key")
                return None
            else:
                self.logger.warning(f"Shodan API error: {response.status_code}")
                return None

        except requests.RequestException as e:
            self.logger.info(f"Error contacting Shodan API: {str(e)}")
            return None

    def _analyze_shodan_data(self, data, results):
        """Analyze Shodan data for security findings"""
        
        # Extract basic information
        if 'ip_str' in data:
            results['findings'].append({
                'type': 'Internet Exposure',
                'severity': 'MEDIUM',
                'description': f'Host {data["ip_str"]} is indexed by Shodan'
            })

        # Check for exposed services
        if 'data' in data:
            services = data['data']
            for service in services:
                port = service.get('port')
                product = service.get('product', 'Unknown')
                version = service.get('version', '')
                
                # Determine severity based on port and service
                severity = self._assess_service_risk(port, product)
                
                results['findings'].append({
                    'type': 'Exposed Service',
                    'severity': severity,
                    'port': port,
                    'service': product,
                    'version': version,
                    'description': f'Port {port} ({product} {version}) exposed to internet'
                })

        # Check for vulnerabilities
        if 'vulns' in data and data['vulns']:
            for vuln in data['vulns']:
                results['findings'].append({
                    'type': 'Known Vulnerability',
                    'severity': 'HIGH',
                    'cve': vuln,
                    'description': f'Host has known vulnerability: {vuln}'
                })

        # Check for certificates (HTTPS services)
        ssl_services = [s for s in data.get('data', []) if s.get('ssl')]
        for service in ssl_services:
            ssl_info = service.get('ssl', {})
            cert = ssl_info.get('cert', {})
            
            # Check certificate issues
            if 'expired' in str(cert).lower():
                results['findings'].append({
                    'type': 'Expired SSL Certificate',
                    'severity': 'MEDIUM',
                    'description': 'SSL certificate appears to be expired'
                })

        # Check for common risky services
        risky_services = self._identify_risky_services(data.get('data', []))
        for service_info in risky_services:
            results['findings'].append({
                'type': 'Risky Service Exposure',
                'severity': service_info['severity'],
                'description': service_info['description']
            })

    def _assess_service_risk(self, port, product):
        """Assess risk level of exposed service"""
        
        # High-risk ports and services
        high_risk = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            110: 'POP3',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            1521: 'Oracle',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            11211: 'Memcached',
            27017: 'MongoDB'
        }

        # Medium-risk ports
        medium_risk = {
            80: 'HTTP',
            443: 'HTTPS',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }

        if port in high_risk:
            return 'HIGH'
        elif port in medium_risk:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _identify_risky_services(self, services):
        """Identify particularly risky service exposures"""
        risky_findings = []
        
        for service in services:
            port = service.get('port')
            product = service.get('product', '').lower()
            banner = service.get('banner', '').lower()
            
            # Check for database exposures
            if any(db in product for db in ['mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch']):
                risky_findings.append({
                    'severity': 'CRITICAL',
                    'description': f'Database service exposed on port {port}: {product}'
                })

            # Check for admin interfaces
            if any(admin in banner for admin in ['admin', 'management', 'console']):
                risky_findings.append({
                    'severity': 'HIGH',
                    'description': f'Administrative interface detected on port {port}'
                })

            # Check for development/debug services
            if any(dev in product for dev in ['debug', 'test', 'dev']):
                risky_findings.append({
                    'severity': 'HIGH',
                    'description': f'Development/debug service exposed on port {port}: {product}'
                })

            # Check for default credentials indicators
            if any(default in banner for default in ['default', 'admin:admin', 'root:root']):
                risky_findings.append({
                    'severity': 'CRITICAL',
                    'description': f'Service with potential default credentials on port {port}'
                })

        return risky_findings
