"""
FTP Scanner Module
Detects open/anonymous FTP services and potential vulnerabilities
"""

import ftplib
import socket
import ssl
import re
import requests
import config


class FTPScanner:
    def __init__(self, logger, timeout=10):
        self.logger = logger
        self.timeout = timeout

    def scan_target(self, target):
        """Scan target for FTP services"""
        results = {
            'target': target,
            'timestamp': self.logger.get_timestamp(),
            'ftp_services': [],
            'pass': True,
            'findings': []
        }

        # Extract hostname/IP
        if target.startswith(('http://', 'https://', 'ftp://')):
            from urllib.parse import urlparse
            hostname = urlparse(target).netloc
        else:
            hostname = target

        # Remove port if specified
        if ':' in hostname and not hostname.count(':') > 1:  # Not IPv6
            hostname = hostname.split(':')[0]

        self.logger.info(f"Scanning FTP service on: {hostname}")

        # Scan default FTP port
        ftp_result = self._scan_ftp_port(hostname, config.FTP_DEFAULT_PORT)
        if ftp_result:
            results['ftp_services'].append(ftp_result)
            
            # Determine severity based on findings
            severity = 'CRITICAL' if ftp_result['anonymous_access'] else 'MEDIUM'
            
            results['pass'] = False
            results['findings'].append({
                'type': 'FTP Service Detected',
                'severity': severity,
                'host': hostname,
                'port': config.FTP_DEFAULT_PORT,
                'details': ftp_result
            })

        # Scan common alternative FTP ports
        alternative_ports = [2121, 990, 989]
        for port in alternative_ports:
            self.logger.info(f"Scanning FTP on alternative port: {port}")
            ftp_result = self._scan_ftp_port(hostname, port)
            if ftp_result:
                results['ftp_services'].append(ftp_result)
                severity = 'CRITICAL' if ftp_result['anonymous_access'] else 'MEDIUM'
                results['pass'] = False
                results['findings'].append({
                    'type': 'FTP Service Detected',
                    'severity': severity,
                    'host': hostname,
                    'port': port,
                    'details': ftp_result
                })

        return results

    def _scan_ftp_port(self, hostname, port):
        """Scan specific FTP port"""
        try:
            # Test basic connectivity
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((hostname, port))
            sock.close()
            
            if result != 0:
                return None

            self.logger.success(f"FTP service found on {hostname}:{port}")

            ftp_info = {
                'host': hostname,
                'port': port,
                'banner': None,
                'anonymous_access': False,
                'server_type': 'Unknown',
                'features': [],
                'directories': [],
                'vulnerabilities': []
            }

            # Connect and get banner
            try:
                ftp = ftplib.FTP()
                ftp.set_debuglevel(0)
                
                # Connect with timeout
                ftp.connect(hostname, port, timeout=self.timeout)
                
                # Get welcome message/banner
                ftp_info['banner'] = ftp.getwelcome()
                
                # Identify server type from banner
                ftp_info['server_type'] = self._identify_server_type(ftp_info['banner'])
                
                # Check for known vulnerabilities based on banner
                ftp_info['vulnerabilities'] = self._check_vulnerabilities(ftp_info['banner'])

                # Test anonymous access
                ftp_info['anonymous_access'] = self._test_anonymous_access(ftp, ftp_info)

                ftp.quit()

            except Exception as e:
                self.logger.info(f"Error during FTP detailed scan: {str(e)}")

            return ftp_info

        except Exception as e:
            self.logger.info(f"Error scanning FTP on {hostname}:{port} - {str(e)}")
            return None

    def _test_anonymous_access(self, ftp, ftp_info):
        """Test for anonymous FTP access"""
        for username in config.FTP_ANONYMOUS_USERS:
            try:
                self.logger.info(f"Testing anonymous login with username: {username}")
                
                # Try anonymous login
                ftp.login(username, 'anonymous@example.com')
                
                self.logger.success(f"Anonymous FTP access successful with username: {username}")
                
                # If successful, try to list directories
                try:
                    directories = ftp.nlst()
                    ftp_info['directories'] = directories[:10]  # Limit to first 10
                    self.logger.info(f"Found {len(directories)} directories/files")
                except Exception:
                    pass

                # Test common FTP commands to gather more info
                try:
                    features = []
                    
                    # Try FEAT command
                    try:
                        feat_response = ftp.sendcmd('FEAT')
                        features.append('FEAT supported')
                    except:
                        pass
                    
                    # Try SYST command
                    try:
                        syst_response = ftp.sendcmd('SYST')
                        features.append(f'System: {syst_response}')
                    except:
                        pass
                    
                    # Try PWD command
                    try:
                        pwd_response = ftp.pwd()
                        features.append(f'Current directory: {pwd_response}')
                    except:
                        pass
                    
                    ftp_info['features'] = features
                    
                except Exception:
                    pass

                return True

            except ftplib.error_perm as e:
                # Login failed, try next username
                self.logger.info(f"Anonymous login failed with {username}: {str(e)}")
                continue
            except Exception as e:
                self.logger.info(f"Error testing anonymous access: {str(e)}")
                continue

        return False

    def _identify_server_type(self, banner):
        """Identify FTP server type from banner"""
        if not banner:
            return 'Unknown'
        
        banner_lower = banner.lower()
        
        server_signatures = {
            'vsftpd': 'vsftpd',
            'proftpd': 'proftpd',
            'pure-ftpd': 'pure-ftpd',
            'wu-ftpd': 'wu-ftpd',
            'microsoft ftp': 'Microsoft IIS FTP',
            'filezilla': 'FileZilla Server',
            'serv-u': 'Serv-U FTP',
            'globalscape': 'GlobalSCAPE',
            'titan ftp': 'Titan FTP'
        }
        
        for signature, server_type in server_signatures.items():
            if signature in banner_lower:
                return server_type
        
        return f'Unknown ({banner.split()[0] if banner.split() else "No banner"})'

    def _check_vulnerabilities(self, banner):
        """Check for known FTP server vulnerabilities based on banner"""
        vulnerabilities = []
        
        if not banner:
            return vulnerabilities
        
        banner_lower = banner.lower()
        
        # Known vulnerable versions (simplified list)
        vulnerable_patterns = {
            'vsftpd 2.3.4': 'CVE-2011-2523 - Backdoor vulnerability',
            'proftpd 1.3.3c': 'CVE-2010-4221 - SQL injection vulnerability',
            'wu-ftpd 2.6.0': 'CVE-1999-0368 - Multiple vulnerabilities',
            'serv-u 15.1.6': 'CVE-2019-12181 - Privilege escalation'
        }
        
        for pattern, vuln_desc in vulnerable_patterns.items():
            if pattern in banner_lower:
                vulnerabilities.append(vuln_desc)
        
        # Check for general indicators
        if 'ftp' in banner_lower and any(word in banner_lower for word in ['2.', '1.', '0.']):
            # This is a basic check - in real scenarios, you'd have a comprehensive CVE database
            vulnerabilities.append('Potentially outdated FTP server - manual verification recommended')
        
        return vulnerabilities
        
    def _scan_ftps_port(self, hostname, port):
        """Scan for FTPS (FTP over SSL/TLS) services"""
        try:
            # Test FTPS implicit SSL (port 990)
            if port == 990:
                return self._test_ftps_implicit(hostname, port)
            else:
                # Test explicit FTPS (STARTTLS)
                return self._test_ftps_explicit(hostname, port)
        except Exception as e:
            self.logger.info(f"FTPS scan error on {hostname}:{port} - {str(e)}")
            return None
            
    def _test_ftps_implicit(self, hostname, port):
        """Test implicit FTPS (SSL from connection start)"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            ftp_tls = ftplib.FTP_TLS(context=context)
            ftp_tls.connect(hostname, port, timeout=self.timeout)
            
            ftps_info = {
                'host': hostname,
                'port': port,
                'type': 'Implicit FTPS',
                'banner': ftp_tls.getwelcome(),
                'ssl_version': None,
                'cipher': None,
                'certificate': None,
                'anonymous_access': False
            }
            
            # Get SSL information
            sock = ftp_tls.sock
            if hasattr(sock, 'version'):
                ftps_info['ssl_version'] = sock.version()
            if hasattr(sock, 'cipher'):
                ftps_info['cipher'] = sock.cipher()
                
            # Get certificate information
            try:
                cert = sock.getpeercert()
                if cert:
                    ftps_info['certificate'] = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'notAfter': cert.get('notAfter'),
                        'notBefore': cert.get('notBefore')
                    }
            except Exception:
                pass
                
            # Test anonymous access
            try:
                ftp_tls.login('anonymous', 'anonymous@example.com')
                ftps_info['anonymous_access'] = True
                self.logger.success(f"Anonymous FTPS access on {hostname}:{port}")
            except Exception:
                pass
                
            ftp_tls.quit()
            return ftps_info
            
        except Exception as e:
            self.logger.info(f"Implicit FTPS test failed: {str(e)}")
            return None
            
    def _test_ftps_explicit(self, hostname, port):
        """Test explicit FTPS (STARTTLS)"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            ftp_tls = ftplib.FTP_TLS(context=context)
            ftp_tls.connect(hostname, port, timeout=self.timeout)
            
            # Try to start TLS
            ftp_tls.auth()
            
            ftps_info = {
                'host': hostname,
                'port': port,
                'type': 'Explicit FTPS (STARTTLS)',
                'banner': ftp_tls.getwelcome(),
                'ssl_version': None,
                'cipher': None,
                'certificate': None,
                'anonymous_access': False
            }
            
            # Get SSL information after STARTTLS
            sock = ftp_tls.sock
            if hasattr(sock, 'version'):
                ftps_info['ssl_version'] = sock.version()
            if hasattr(sock, 'cipher'):
                ftps_info['cipher'] = sock.cipher()
                
            # Get certificate information
            try:
                cert = sock.getpeercert()
                if cert:
                    ftps_info['certificate'] = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'notAfter': cert.get('notAfter'),
                        'notBefore': cert.get('notBefore')
                    }
            except Exception:
                pass
                
            # Test anonymous access
            try:
                ftp_tls.login('anonymous', 'anonymous@example.com')
                ftps_info['anonymous_access'] = True
                self.logger.success(f"Anonymous FTPS access on {hostname}:{port}")
            except Exception:
                pass
                
            ftp_tls.quit()
            return ftps_info
            
        except Exception as e:
            self.logger.info(f"Explicit FTPS test failed: {str(e)}")
            return None
            
    def _check_ssl_configuration(self, ssl_info):
        """Check SSL/TLS configuration for security issues"""
        issues = []
        
        if not ssl_info:
            return issues
            
        # Check SSL version
        ssl_version = ssl_info.get('ssl_version', '')
        if any(weak in ssl_version.lower() for weak in ['sslv2', 'sslv3', 'tlsv1.0', 'tlsv1.1']):
            issues.append(f"Weak SSL/TLS version: {ssl_version}")
            
        # Check cipher strength
        cipher = ssl_info.get('cipher')
        if cipher:
            cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)
            if any(weak in cipher_name.lower() for weak in ['rc4', 'des', 'md5', 'null']):
                issues.append(f"Weak cipher detected: {cipher_name}")
                
        # Check certificate validity
        cert = ssl_info.get('certificate')
        if cert:
            import datetime
            try:
                not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                if not_after < datetime.datetime.now():
                    issues.append("SSL certificate has expired")
            except Exception:
                pass
                
        return issues
        
    def _query_cve_database(self, server_type, version):
        """Query CVE database for known vulnerabilities"""
        vulnerabilities = []
        
        # This is a simplified example - in production, you'd use a proper CVE API
        try:
            # Example: Query NVD API (requires proper implementation)
            query = f"{server_type} {version}"
            # cve_results = self._search_nvd_api(query)
            # vulnerabilities.extend(cve_results)
            
            # For now, return known patterns
            known_vulns = {
                'vsftpd 2.3.4': ['CVE-2011-2523'],
                'proftpd 1.3.3c': ['CVE-2010-4221'],
                'wu-ftpd 2.6.0': ['CVE-1999-0368']
            }
            
            key = f"{server_type.lower()} {version}"
            if key in known_vulns:
                vulnerabilities.extend(known_vulns[key])
                
        except Exception as e:
            self.logger.info(f"CVE database query failed: {str(e)}")
            
        return vulnerabilities
