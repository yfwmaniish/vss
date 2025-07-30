#!/usr/bin/env python3
"""
HMS - Advanced Port Scanner
Performs comprehensive port scanning with service detection, version identification, 
and vulnerability assessment for discovered services.
"""

import asyncio
import socket
import json
import logging
import time
import re
import ssl
import aiohttp
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse

class AdvancedPortScanner:
    def __init__(self, timeout: int = 3, max_concurrent: int = 100):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.logger = logging.getLogger(__name__)
        
        # Service signatures for identification
        self.service_signatures = {
            'http': {
                'ports': [80, 8080, 8000, 8888, 9090],
                'probes': [b'GET / HTTP/1.1\r\nHost: {host}\r\n\r\n'],
                'signatures': [
                    (re.compile(rb'Server:\s*([^\r\n]+)', re.IGNORECASE), 'server'),
                    (re.compile(rb'Apache/(\d+\.\d+\.\d+)', re.IGNORECASE), 'apache_version'),
                    (re.compile(rb'nginx/(\d+\.\d+\.\d+)', re.IGNORECASE), 'nginx_version'),
                    (re.compile(rb'Microsoft-IIS/(\d+\.\d+)', re.IGNORECASE), 'iis_version'),
                ]
            },
            'https': {
                'ports': [443, 8443, 9443],
                'probes': [b'GET / HTTP/1.1\r\nHost: {host}\r\n\r\n'],
                'signatures': [
                    (re.compile(rb'Server:\s*([^\r\n]+)', re.IGNORECASE), 'server'),
                    (re.compile(rb'Apache/(\d+\.\d+\.\d+)', re.IGNORECASE), 'apache_version'),
                    (re.compile(rb'nginx/(\d+\.\d+\.\d+)', re.IGNORECASE), 'nginx_version'),
                ]
            },
            'ssh': {
                'ports': [22, 2222],
                'probes': [b'SSH-2.0-Scanner\r\n'],
                'signatures': [
                    (re.compile(rb'SSH-(\d+\.\d+)-OpenSSH_(\d+\.\d+)', re.IGNORECASE), 'openssh_version'),
                    (re.compile(rb'SSH-(\d+\.\d+)-([^\r\n]+)', re.IGNORECASE), 'ssh_version'),
                ]
            },
            'ftp': {
                'ports': [21, 2121],
                'probes': [b''],
                'signatures': [
                    (re.compile(rb'220.*vsftpd (\d+\.\d+\.\d+)', re.IGNORECASE), 'vsftpd_version'),
                    (re.compile(rb'220.*ProFTPD (\d+\.\d+\.\d+)', re.IGNORECASE), 'proftpd_version'),
                    (re.compile(rb'220.*Microsoft FTP Service', re.IGNORECASE), 'ms_ftp'),
                ]
            },
            'smtp': {
                'ports': [25, 587, 465],
                'probes': [b''],
                'signatures': [
                    (re.compile(rb'220.*Postfix', re.IGNORECASE), 'postfix'),
                    (re.compile(rb'220.*Sendmail', re.IGNORECASE), 'sendmail'),
                    (re.compile(rb'220.*Microsoft ESMTP', re.IGNORECASE), 'ms_smtp'),
                ]
            },
            'mysql': {
                'ports': [3306],
                'probes': [b''],
                'signatures': [
                    (re.compile(rb'(\d+\.\d+\.\d+)-.*mysql', re.IGNORECASE), 'mysql_version'),
                ]
            }
        }
        
        # Known vulnerabilities database (simplified)
        self.vulnerability_db = {
            'apache': {
                '2.4.49': ['CVE-2021-41773', 'CVE-2021-42013'],
                '2.4.48': ['CVE-2021-34798', 'CVE-2021-39275'],
                '2.4.46': ['CVE-2021-26690', 'CVE-2021-26691'],
                '2.2.34': ['CVE-2017-15710', 'CVE-2017-15715'],
            },
            'nginx': {
                '1.20.0': ['CVE-2021-23017'],
                '1.19.0': ['CVE-2019-20372'],
                '1.16.1': ['CVE-2019-9511', 'CVE-2019-9513'],
            },
            'openssh': {
                '8.0': ['CVE-2020-15778'],
                '7.4': ['CVE-2018-15473'],
                '6.6': ['CVE-2016-0777', 'CVE-2016-0778'],
            },
            'mysql': {
                '8.0.26': ['CVE-2021-35604'],
                '5.7.35': ['CVE-2021-35604'],
                '5.6.51': ['CVE-2021-2372'],
            },
            'gunicorn': {
                '19.9.0': ['CVE-2018-1000164'],
                '19.7.1': ['CVE-2018-1000164'],
                '20.0.4': ['CVE-2018-1000164'],
            },
            'werkzeug': {
                '2.0.0': ['CVE-2023-25577'],
                '1.0.1': ['CVE-2020-28724'],
                '0.15.3': ['CVE-2019-14806'],
            },
            'jetty': {
                '9.4.43': ['CVE-2021-34429'],
                '9.4.41': ['CVE-2021-28169'],
                '11.0.6': ['CVE-2021-34429'],
            }
        }

    async def scan(self, target: str, ports: List[int] = None) -> Dict[str, Any]:
        """
        Main scanning function with advanced service detection
        """
        if ports is None:
            ports = list(range(1, 1001))  # Default port range
            
        self.logger.info(f"Starting advanced port scan for {target}")
        
        results = {
            'target': target,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'findings': [],
            'open_ports': [],
            'services': {},
            'vulnerabilities': [],
            'stats': {
                'total_scanned': len(ports),
                'total_open': 0,
                'services_identified': 0,
                'vulnerabilities_found': 0
            }
        }
        
        try:
            # Phase 1: Basic port scanning
            open_ports = await self._scan_ports_basic(target, ports)
            results['open_ports'] = sorted(open_ports)
            results['stats']['total_open'] = len(open_ports)
            
            # Phase 2: Service detection and banner grabbing
            if open_ports:
                services = await self._detect_services(target, open_ports)
                results['services'] = services
                results['stats']['services_identified'] = len([s for s in services.values() if s.get('service')])
                
                # Phase 3: Vulnerability assessment
                vulnerabilities = self._assess_vulnerabilities(services)
                results['vulnerabilities'] = vulnerabilities
                results['stats']['vulnerabilities_found'] = len(vulnerabilities)
                
                # Create findings
                self._create_findings(results, open_ports, services, vulnerabilities)
                
        except Exception as e:
            self.logger.error(f"Error during advanced port scan: {e}")
            results['findings'].append({
                'type': 'Scan Error',
                'severity': 'ERROR',
                'description': f'Error during advanced port scan: {str(e)}'
            })
            
        return results

    async def _scan_ports_basic(self, target: str, ports: List[int]) -> List[int]:
        """Basic port connectivity check"""
        open_ports = []
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def check_port(port):
            async with semaphore:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port), 
                        timeout=self.timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    return port
                except:
                    return None
        
        tasks = [check_port(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        open_ports = [port for port in results if port is not None]
        
        return open_ports

    async def _detect_services(self, target: str, ports: List[int]) -> Dict[int, Dict[str, Any]]:
        """Advanced service detection with banner grabbing"""
        services = {}
        semaphore = asyncio.Semaphore(50)  # Lower concurrency for service detection
        
        async def detect_service(port):
            async with semaphore:
                service_info = {
                    'port': port,
                    'service': None,
                    'version': None,
                    'banner': None,
                    'ssl_enabled': False,
                    'details': {}
                }
                
                try:
                    # Try to identify service type based on port
                    service_type = self._guess_service_by_port(port)
                    
                    if service_type in ['http', 'https']:
                        service_info.update(await self._probe_http_service(target, port, service_type == 'https'))
                    elif service_type == 'ssh':
                        service_info.update(await self._probe_ssh_service(target, port))
                    elif service_type in ['ftp', 'smtp', 'mysql']:
                        service_info.update(await self._probe_generic_service(target, port, service_type))
                    else:
                        # Generic banner grab
                        service_info.update(await self._probe_generic_service(target, port, 'unknown'))
                        
                except Exception as e:
                    self.logger.debug(f"Service detection failed for {target}:{port} - {e}")
                    service_info['error'] = str(e)
                
                return port, service_info
        
        tasks = [detect_service(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, tuple) and len(result) == 2:
                port, service_info = result
                services[port] = service_info
                
        return services

    def _guess_service_by_port(self, port: int) -> str:
        """Guess service type based on common port assignments"""
        for service_type, config in self.service_signatures.items():
            if port in config['ports']:
                return service_type
        return 'unknown'

    async def _probe_http_service(self, target: str, port: int, use_ssl: bool = False) -> Dict[str, Any]:
        """Probe HTTP/HTTPS services"""
        info = {'service': 'http' if not use_ssl else 'https'}
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            connector = aiohttp.TCPConnector(ssl=False if not use_ssl else ssl.create_default_context())
            
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                url = f"{'https' if use_ssl else 'http'}://{target}:{port}/"
                async with session.get(url) as response:
                    info['status_code'] = response.status
                    info['banner'] = str(response.headers)
                    
                    # Extract server information
                    server_header = response.headers.get('Server', '')
                    if server_header:
                        info['server'] = server_header
                        
                        # Extract version information
                        if 'Apache/' in server_header:
                            match = re.search(r'Apache/(\d+\.\d+\.\d+)', server_header)
                            if match:
                                info['service'] = 'apache'
                                info['version'] = match.group(1)
                        elif 'nginx/' in server_header:
                            match = re.search(r'nginx/(\d+\.\d+\.\d+)', server_header)
                            if match:
                                info['service'] = 'nginx'
                                info['version'] = match.group(1)
                        elif 'Microsoft-IIS/' in server_header:
                            match = re.search(r'Microsoft-IIS/(\d+\.\d+)', server_header)
                            if match:
                                info['service'] = 'iis'
                                info['version'] = match.group(1)
                        elif 'gunicorn/' in server_header:
                            match = re.search(r'gunicorn/(\d+\.\d+\.\d+)', server_header)
                            if match:
                                info['service'] = 'gunicorn'
                                info['version'] = match.group(1)
                        elif 'Werkzeug/' in server_header:
                            match = re.search(r'Werkzeug/(\d+\.\d+\.\d+)', server_header)
                            if match:
                                info['service'] = 'werkzeug'
                                info['version'] = match.group(1)
                        elif 'Jetty(' in server_header:
                            match = re.search(r'Jetty\((\d+\.\d+\.\d+)', server_header)
                            if match:
                                info['service'] = 'jetty'
                                info['version'] = match.group(1)
                    
                    info['ssl_enabled'] = use_ssl
                    
        except Exception as e:
            info['error'] = str(e)
            
        return info

    async def _probe_ssh_service(self, target: str, port: int) -> Dict[str, Any]:
        """Probe SSH services"""
        info = {'service': 'ssh'}
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), 
                timeout=self.timeout
            )
            
            # SSH servers send their banner immediately
            banner = await asyncio.wait_for(reader.readline(), timeout=2)
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            info['banner'] = banner_str
            
            # Extract SSH version
            if 'OpenSSH_' in banner_str:
                match = re.search(r'OpenSSH_(\d+\.\d+)', banner_str)
                if match:
                    info['service'] = 'openssh'
                    info['version'] = match.group(1)
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            info['error'] = str(e)
            
        return info

    async def _probe_generic_service(self, target: str, port: int, service_type: str) -> Dict[str, Any]:
        """Generic service probing with banner grabbing"""
        info = {'service': service_type}
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), 
                timeout=self.timeout
            )
            
            # Try to read banner
            try:
                banner = await asyncio.wait_for(reader.read(1024), timeout=2)
                banner_str = banner.decode('utf-8', errors='ignore')
                info['banner'] = banner_str
                
                # Apply service-specific signatures
                if service_type in self.service_signatures:
                    for pattern, info_type in self.service_signatures[service_type]['signatures']:
                        match = pattern.search(banner)
                        if match:
                            if info_type.endswith('_version'):
                                info['version'] = match.group(1) if match.groups() else match.group(0)
                                info['service'] = info_type.replace('_version', '')
                            else:
                                info[info_type] = match.group(1) if match.groups() else match.group(0)
                
            except asyncio.TimeoutError:
                pass  # No banner available
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            info['error'] = str(e)
            
        return info

    def _assess_vulnerabilities(self, services: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Assess vulnerabilities based on identified services and versions"""
        vulnerabilities = []
        
        for port, service_info in services.items():
            service = service_info.get('service')
            version = service_info.get('version')
            
            if service and version:
                # Check vulnerability database
                if service in self.vulnerability_db:
                    service_vulns = self.vulnerability_db[service]
                    if version in service_vulns:
                        for cve in service_vulns[version]:
                            vuln = {
                                'port': port,
                                'service': service,
                                'version': version,
                                'cve': cve,
                                'severity': self._get_cve_severity(cve),
                                'description': f'{service} {version} is vulnerable to {cve}'
                            }
                            vulnerabilities.append(vuln)
                
                # Check for general service vulnerabilities
                vulns = self._check_service_vulnerabilities(service, version, service_info)
                vulnerabilities.extend(vulns)
        
        return vulnerabilities

    def _get_cve_severity(self, cve: str) -> str:
        """Get CVE severity (simplified implementation)"""
        # In a real implementation, this would query CVE databases
        high_risk_cves = ['CVE-2021-41773', 'CVE-2021-42013', 'CVE-2020-15778']
        if cve in high_risk_cves:
            return 'CRITICAL'
        return 'HIGH'

    def _check_service_vulnerabilities(self, service: str, version: str, service_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for additional service-specific vulnerabilities"""
        vulnerabilities = []
        port = service_info.get('port')
        
        # Check for outdated versions (simplified)
        outdated_versions = {
            'apache': '2.4.50',
            'nginx': '1.21.0',
            'openssh': '8.7',
            'mysql': '8.0.27'
        }
        
        if service in outdated_versions:
            try:
                current_version = tuple(map(int, version.split('.')))
                latest_version = tuple(map(int, outdated_versions[service].split('.')))
                
                if current_version < latest_version:
                    vulnerabilities.append({
                        'port': port,
                        'service': service,
                        'version': version,
                        'type': 'outdated_version',
                        'severity': 'MEDIUM',
                        'description': f'{service} {version} is outdated. Latest version: {outdated_versions[service]}'
                    })
            except ValueError:
                pass  # Version comparison failed
        
        # Check for weak SSL/TLS configurations
        if service_info.get('ssl_enabled') and service in ['https', 'http']:
            # This would require additional SSL/TLS testing
            pass
        
        return vulnerabilities

    def _create_findings(self, results: Dict[str, Any], open_ports: List[int], 
                        services: Dict[int, Dict[str, Any]], vulnerabilities: List[Dict[str, Any]]):
        """Create findings from scan results"""
        
        # Open port findings
        for port in open_ports:
            service_info = services.get(port, {})
            service_name = service_info.get('service', 'unknown')
            version = service_info.get('version', 'unknown')
            
            finding = {
                'type': 'Open Port',
                'severity': 'INFO',
                'port': port,
                'service': service_name,
                'version': version,
                'description': f'Open port {port} running {service_name}' + 
                              (f' version {version}' if version != 'unknown' else '')
            }
            
            if service_info.get('banner'):
                finding['banner'] = service_info['banner'][:200]  # Truncate long banners
                
            results['findings'].append(finding)
        
        # Vulnerability findings
        for vuln in vulnerabilities:
            finding = {
                'type': 'Service Vulnerability',
                'severity': vuln.get('severity', 'MEDIUM'),
                'port': vuln['port'],
                'service': vuln['service'],
                'version': vuln.get('version'),
                'description': vuln['description']
            }
            
            if 'cve' in vuln:
                finding['cve'] = vuln['cve']
                
            results['findings'].append(finding)

# Example usage
if __name__ == "__main__":
    async def main():
        scanner = AdvancedPortScanner()
        results = await scanner.scan("httpbin.org", [22, 80, 443, 8080])
        print(json.dumps(results, indent=2))
    
    asyncio.run(main())
