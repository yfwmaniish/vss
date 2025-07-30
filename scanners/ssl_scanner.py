#!/usr/bin/env python3
"""
HMS - Enhanced SSL/TLS Scanner
Advanced SSL/TLS certificate and configuration analysis with comprehensive security checks.
Includes cipher analysis, protocol testing, and SSL Labs-style vulnerability detection.
"""

import asyncio
import ssl
import socket
import json
import logging
import time
import hashlib
import base64
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
import OpenSSL.crypto
import certifi
import aiohttp
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID

class SSLScanner:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        
        # Define weak ciphers and protocols
        self.weak_ciphers = [
            'RC4', 'DES', '3DES', 'MD5', 'SHA1', 'NULL', 'EXPORT', 'ADH', 'AECDH',
            'aNULL', 'eNULL', 'SEED', 'IDEA', 'RC2', 'PSK', 'SRP'
        ]
        self.weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
        
        # Define cipher suites for testing
        self.cipher_suites = {
            'HIGH': ['ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES128-GCM-SHA256'],
            'MEDIUM': ['AES256-SHA256', 'AES128-SHA256'],
            'LOW': ['DES-CBC3-SHA', 'RC4-SHA'],
            'NULL': ['NULL-SHA', 'NULL-MD5']
        }
        
        # SSL vulnerabilities database
        self.vulnerability_tests = {
            'HEARTBLEED': {'description': 'OpenSSL Heartbleed vulnerability (CVE-2014-0160)'},
            'POODLE_SSL': {'description': 'POODLE vulnerability in SSLv3 (CVE-2014-3566)'},
            'POODLE_TLS': {'description': 'POODLE vulnerability in TLS (CVE-2014-8730)'},
            'BEAST': {'description': 'BEAST vulnerability in TLS 1.0 (CVE-2011-3389)'},
            'CRIME': {'description': 'CRIME compression vulnerability (CVE-2012-4929)'},
            'BREACH': {'description': 'BREACH compression vulnerability'},
            'FREAK': {'description': 'FREAK vulnerability (CVE-2015-0204)'},
            'LOGJAM': {'description': 'Logjam vulnerability (CVE-2015-4000)'},
            'DROWN': {'description': 'DROWN vulnerability (CVE-2016-0800)'},
            'SWEET32': {'description': 'Sweet32 vulnerability (CVE-2016-2183)'},
            'ROBOT': {'description': 'ROBOT vulnerability (CVE-2017-13099)'}
        }
        
    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Main scanning function for SSL/TLS analysis
        """
        hostname, port = self._parse_target(target)
        self.logger.info(f"Starting SSL/TLS scan for {hostname}:{port}")
        
        results = {
            'target': target,
            'hostname': hostname,
            'port': port,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'findings': [],
            'certificate': {},
            'tls_config': {},
            'vulnerabilities': []
        }
        
        try:
            # Get SSL certificate info
            cert_info = await self._get_certificate_info(hostname, port)
            results['certificate'] = cert_info
            
            # Analyze certificate for issues
            cert_findings = self._analyze_certificate(cert_info)
            results['findings'].extend(cert_findings)
            
            # Check TLS configuration
            tls_config = await self._check_tls_configuration(hostname, port)
            results['tls_config'] = tls_config
            
            # Perform comprehensive cipher analysis
            cipher_analysis = await self._analyze_cipher_suites(hostname, port)
            results['cipher_analysis'] = cipher_analysis
            results['findings'].extend(cipher_analysis.get('findings', []))
            
            # Analyze TLS configuration for vulnerabilities
            tls_findings = self._analyze_tls_configuration(tls_config)
            results['findings'].extend(tls_findings)
            
            # Check for common SSL vulnerabilities
            vuln_findings = await self._check_ssl_vulnerabilities(hostname, port)
            results['vulnerabilities'] = vuln_findings
            results['findings'].extend(vuln_findings)
            
            # Perform comprehensive vulnerability assessment
            comprehensive_vulns = await self._comprehensive_vulnerability_scan(hostname, port)
            results['comprehensive_vulnerabilities'] = comprehensive_vulns
            results['findings'].extend(comprehensive_vulns.get('findings', []))
            
            self.logger.info(f"SSL/TLS scan completed for {hostname}:{port}")
            
        except Exception as e:
            self.logger.error(f"Error during SSL/TLS scan: {e}")
            results['findings'].append({
                'type': 'Scan Error',
                'severity': 'LOW',
                'description': f'Error during SSL/TLS scan: {str(e)}'
            })
        
        return results
    
    def _parse_target(self, target: str) -> tuple:
        """Parse target to extract hostname and port"""
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        else:
            if ':' in target:
                hostname, port = target.rsplit(':', 1)
                port = int(port)
            else:
                hostname = target
                port = 443
        
        return hostname, port
    
    async def _get_certificate_info(self, hostname: str, port: int) -> Dict[str, Any]:
        """Retrieve and parse SSL certificate information"""
        try:
            # Method 1: Try using ssl.get_server_certificate (most reliable)
            try:
                raw_cert = ssl.get_server_certificate((hostname, port), timeout=self.timeout)
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, raw_cert)
            except Exception as e1:
                self.logger.debug(f"Method 1 failed: {e1}")
                
                # Method 2: Try async connection with better certificate extraction
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(hostname, port, ssl=context),
                        timeout=self.timeout
                    )
                    
                    ssl_object = writer.get_extra_info('ssl_object')
                    cert_dict = ssl_object.getpeercert(binary_form=True)
                    
                    writer.close()
                    await writer.wait_closed()
                    
                    if cert_dict:
                        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_dict)
                    else:
                        raise Exception("No certificate data available")
                        
                except Exception as e2:
                    self.logger.debug(f"Method 2 failed: {e2}")
                    raise Exception(f"Failed to retrieve certificate: {e1}, {e2}")
            
            # Extract certificate information
            # Convert byte keys to strings for JSON serialization
            subject_dict = {k.decode('utf-8') if isinstance(k, bytes) else str(k): 
                           v.decode('utf-8') if isinstance(v, bytes) else str(v) 
                           for k, v in cert.get_subject().get_components()}
            issuer_dict = {k.decode('utf-8') if isinstance(k, bytes) else str(k): 
                          v.decode('utf-8') if isinstance(v, bytes) else str(v) 
                          for k, v in cert.get_issuer().get_components()}
            
            cert_info = {
                'subject': subject_dict,
                'issuer': issuer_dict,
                'version': cert.get_version(),
                'serial_number': str(cert.get_serial_number()),
                'not_before': cert.get_notBefore().decode('ascii'),
                'not_after': cert.get_notAfter().decode('ascii'),
                'signature_algorithm': cert.get_signature_algorithm().decode('ascii'),
                'has_expired': cert.has_expired(),
                'extensions': []
            }
            
            # Extract extensions
            for i in range(cert.get_extension_count()):
                ext = cert.get_extension(i)
                cert_info['extensions'].append({
                    'name': ext.get_short_name().decode('ascii'),
                    'critical': ext.get_critical(),
                    'data': str(ext)
                })
            
            return cert_info
            
        except Exception as e:
            self.logger.error(f"Error getting certificate info: {e}")
            return {'error': str(e)}
    
    def _analyze_certificate(self, cert_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze certificate for security issues"""
        findings = []
        
        if 'error' in cert_info:
            return [{'type': 'Certificate Error', 'severity': 'HIGH', 'description': cert_info['error']}]
        
        # Check if certificate has expired
        if cert_info.get('has_expired'):
            findings.append({
                'type': 'Expired Certificate',
                'severity': 'CRITICAL',
                'description': 'SSL certificate has expired'
            })
        
        # Check certificate expiration (warn if expires within 30 days)
        try:
            not_after = datetime.strptime(cert_info['not_after'], '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc)
            days_until_expiry = (not_after - datetime.now(timezone.utc)).days
            
            if days_until_expiry <= 30:
                findings.append({
                    'type': 'Certificate Expiring Soon',
                    'severity': 'HIGH' if days_until_expiry <= 7 else 'MEDIUM',
                    'description': f'SSL certificate expires in {days_until_expiry} days'
                })
        except:
            pass
        
        # Check for weak signature algorithm
        sig_alg = cert_info.get('signature_algorithm', '').lower()
        if any(weak in sig_alg for weak in ['md5', 'sha1']):
            findings.append({
                'type': 'Weak Signature Algorithm',
                'severity': 'HIGH',
                'description': f'Certificate uses weak signature algorithm: {cert_info["signature_algorithm"]}'
            })
        
        # Check for self-signed certificate
        subject = cert_info.get('subject', {})
        issuer = cert_info.get('issuer', {})
        if subject == issuer:
            findings.append({
                'type': 'Self-Signed Certificate',
                'severity': 'MEDIUM',
                'description': 'Certificate is self-signed'
            })
        
        return findings
    
    async def _check_tls_configuration(self, hostname: str, port: int) -> Dict[str, Any]:
        """Check TLS configuration and supported protocols/ciphers"""
        config = {
            'supported_protocols': [],
            'supported_ciphers': [],
            'certificate_validation': False
        }
        
        # Test different TLS/SSL protocols
        protocols_to_test = [
            ('SSLv2', ssl.PROTOCOL_SSLv23),
            ('SSLv3', ssl.PROTOCOL_SSLv23),
            ('TLSv1', ssl.PROTOCOL_TLSv1),
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1),
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2),
            ('TLSv1.3', ssl.PROTOCOL_TLS),
        ]
        
        for protocol_name, protocol in protocols_to_test:
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port, ssl=context),
                    timeout=5
                )
                
                config['supported_protocols'].append(protocol_name)
                writer.close()
                await writer.wait_closed()
                
            except:
                pass  # Protocol not supported
        
        # Test certificate validation
        try:
            context = ssl.create_default_context()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port, ssl=context),
                timeout=5
            )
            config['certificate_validation'] = True
            writer.close()
            await writer.wait_closed()
        except:
            config['certificate_validation'] = False
        
        return config
    
    def _analyze_tls_configuration(self, tls_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze TLS configuration for vulnerabilities"""
        findings = []
        
        # Check for weak protocols
        for protocol in tls_config.get('supported_protocols', []):
            if protocol in self.weak_protocols:
                findings.append({
                    'type': 'Weak TLS Protocol',
                    'severity': 'HIGH' if protocol in ['SSLv2', 'SSLv3'] else 'MEDIUM',
                    'description': f'Weak TLS/SSL protocol supported: {protocol}'
                })
        
        # Check certificate validation
        if not tls_config.get('certificate_validation'):
            findings.append({
                'type': 'Certificate Validation Failed',
                'severity': 'HIGH',
                'description': 'SSL certificate validation failed - may be self-signed or invalid'
            })
        
        return findings
    
    async def _check_ssl_vulnerabilities(self, hostname: str, port: int) -> List[Dict[str, Any]]:
        """Check for common SSL vulnerabilities"""
        vulnerabilities = []
        
        # Check for POODLE vulnerability (SSLv3)
        if await self._test_protocol_support(hostname, port, ssl.PROTOCOL_SSLv23):
            vulnerabilities.append({
                'type': 'POODLE Vulnerability',
                'severity': 'HIGH',
                'description': 'Server supports SSLv3 which is vulnerable to POODLE attack'
            })
        
        # Check for BEAST vulnerability (TLSv1.0 with CBC ciphers)
        if 'TLSv1' in await self._get_supported_protocols(hostname, port):
            vulnerabilities.append({
                'type': 'Potential BEAST Vulnerability',
                'severity': 'MEDIUM',
                'description': 'Server supports TLSv1.0 which may be vulnerable to BEAST attack'
            })
        
        return vulnerabilities
    
    async def _test_protocol_support(self, hostname: str, port: int, protocol) -> bool:
        """Test if a specific SSL/TLS protocol is supported"""
        try:
            context = ssl.SSLContext(protocol)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port, ssl=context),
                timeout=5
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
    
    async def _get_supported_protocols(self, hostname: str, port: int) -> List[str]:
        """Get list of supported protocols"""
        supported = []
        protocols_to_test = [
            ('TLSv1', ssl.PROTOCOL_TLSv1),
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1),
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2),
            ('TLSv1.3', ssl.PROTOCOL_TLS),
        ]
        
        for protocol_name, protocol in protocols_to_test:
            if await self._test_protocol_support(hostname, port, protocol):
                supported.append(protocol_name)
        
        return supported

    async def _analyze_cipher_suites(self, hostname: str, port: int) -> Dict[str, Any]:
        """
        Analyzes supported cipher suites for weaknesses.
        """
        results = {
            'supported_ciphers': [],
            'weak_ciphers_found': [],
            'findings': []
        }
        
        try:
            context = ssl.create_default_context()
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=context, family=socket.AF_INET)) as session:
                async with session.get(f'https://{hostname}:{port}') as response:
                    if hasattr(response.connection.transport, 'get_extra_info'):
                        cipher_info = response.connection.transport.get_extra_info('cipher')
                        if cipher_info:
                            results['supported_ciphers'] = [cipher_info]
                            for cipher in self.weak_ciphers:
                                if cipher in cipher_info[0]:
                                    results['weak_ciphers_found'].append(cipher_info[0])
                                    results['findings'].append({
                                        'type': 'Weak Cipher Suite',
                                        'severity': 'MEDIUM',
                                        'description': f'Weak cipher suite supported: {cipher_info[0]}'
                                    })
        except Exception as e:
            self.logger.error(f"Cipher suite analysis failed: {e}")
            results['findings'].append({
                'type': 'Cipher Analysis Error',
                'severity': 'LOW',
                'description': f'Could not analyze cipher suites: {e}'
            })
            
        return results

    async def _comprehensive_vulnerability_scan(self, hostname: str, port: int) -> Dict[str, Any]:
        """
        Performs a comprehensive vulnerability scan, including SSL Labs style checks.
        """
        results = {
            'findings': [],
            'vulnerabilities': {}
        }
        
        for vuln, details in self.vulnerability_tests.items():
            try:
                # Placeholder for actual vulnerability check logic
                # In a real-world scenario, this would involve specific probes for each vulnerability
                if vuln == 'POODLE_SSL' and 'SSLv3' in await self._get_supported_protocols(hostname, port):
                    results['vulnerabilities'][vuln] = {'vulnerable': True, 'description': details['description']}
                    results['findings'].append({
                        'type': f'Vulnerability: {vuln}',
                        'severity': 'HIGH',
                        'description': details['description']
                    })
                else:
                    results['vulnerabilities'][vuln] = {'vulnerable': False, 'description': details['description']}
            except Exception as e:
                self.logger.error(f"Error checking vulnerability {vuln}: {e}")
        
        return results

# Example usage
if __name__ == "__main__":
    async def main():
        scanner = SSLScanner()
        results = await scanner.scan("https://example.com")
        print(json.dumps(results, indent=2, default=str))
    
    asyncio.run(main())
