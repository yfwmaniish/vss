#!/usr/bin/env python3
"""
HMS - Enhanced Port Scanner
Performs port scanning with service detection, version identification, and vulnerability assessment.
"""

import asyncio
import socket
import json
import logging
import time
import re
import ssl
import aiohttp
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

class PortScanner:
    def __init__(self, timeout: int = 1, max_concurrent: int = 500):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.logger = logging.getLogger(__name__)
        
    async def scan(self, target: str, ports: List[int]) -> Dict[str, Any]:
        """
        Main scanning function to identify open ports on the target
        """
        self.logger.info(f"Starting port scan for {target}")

        results = {
            'target': target,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'findings': [],
            'open_ports': [],
            'stats': {
                'total_scanned': len(ports),
                'total_open': 0
            }
        }

        try:
            # Scan ports concurrently
            open_ports = await self._scan_ports(target, ports)
            
            # Format results
            results['open_ports'] = sorted(open_ports)
            results['stats']['total_open'] = len(open_ports)
            
            # Create findings for open ports
            for port in open_ports:
                results['findings'].append({
                    'type': 'Open Port',
                    'severity': 'INFO',
                    'description': f'Open port discovered: {port}',
                    'port': port,
                    'status': 'open'
                })

            self.logger.info(f"Found {len(open_ports)} open ports on {target}")

        except Exception as e:
            self.logger.error(f"Error during port scan: {e}")
            results['findings'].append({
                'type': 'Scan Error',
                'severity': 'LOW',
                'description': f'Error during port scan: {str(e)}'
            })

        return results

    async def _scan_ports(self, target: str, ports: List[int]) -> List[int]:
        """Check specified ports on the given target"""
        open_ports = []
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def check_port(port):
            async with semaphore:
                try:
                    # Open connection to the port
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=self.timeout)
                    open_ports.append(port)
                    self.logger.debug(f"Port {port} is open on {target}")

                    # Attempt to grab the service banner or check version
                    banner = await self._grab_banner(target, port, reader)
                    service_info = self._identify_service(banner)
                    vulnerabilities = self._check_vulnerabilities(service_info)

                    # Log service info and vulnerabilities
                    if service_info:
                        self.logger.info(f"Port {port} service: {service_info}")
                    if vulnerabilities:
                        self.logger.warning(f"Port {port} vulnerabilities: {vulnerabilities}")

                    # Close the writer
                    writer.close()
                    await writer.wait_closed()

                except Exception as e:
                    self.logger.error(f"Failed to connect to {target}:{port} - {e}")

        # Create tasks for all ports
        tasks = [check_port(port) for port in ports]
        await asyncio.gather(*tasks, return_exceptions=True)

        return open_ports

    async def _grab_banner(self, target: str, port: int, reader) -> Optional[str]:
        """Attempt to grab the banner of a service"""
        try:
            # Send a blank request to provoke a response
            await reader.read(1024)
            return reader.read(1024).decode(errors='ignore')
        except Exception as e:
            self.logger.debug(f"Failed to grab banner from {target}:{port} - {e}")
        return None

    def _identify_service(self, banner: Optional[str]) -> Optional[str]:
        """Identify service from the banner"""
        if not banner:
            return None
        # Very rudimentary banner analysis
        if 'Apache' in banner:
            return 'Apache HTTP Server'
        elif 'nginx' in banner:
            return 'Nginx'
        elif 'SSH' in banner:
            return 'OpenSSH'
        return 'Unknown'

    def _check_vulnerabilities(self, service_info: Optional[str]) -> List[str]:
        """Check known vulnerabilities for a service"""
        # Rudimentary vulnerability check
        vulnerabilities = []
        if service_info == 'Apache HTTP Server':
            vulnerabilities.append('CVE-2021-41773')  # Example CVE
        if service_info == 'OpenSSH':
            vulnerabilities.append('CVE-2020-15778')  # Example CVE
        return vulnerabilities

# Example usage
if __name__ == "__main__":
    async def main():
        scanner = PortScanner()
        target_ports = range(1, 1025)  # Common first 1024 ports
        results = await scanner.scan("example.com", target_ports)
        print(json.dumps(results, indent=2))
    
    asyncio.run(main())

