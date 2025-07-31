import asyncio
from googlesearch import search
from utils.logger import Logger
import time
import random
from datetime import datetime

class FocusedDorkingScanner:
    def __init__(self, logger: Logger, timeout: int = 10):
        self.logger = logger
        self.timeout = timeout
        self.dorks = {
            "Critical Files": [
                'filetype:env',
                'filetype:sql',
                'inurl:.git',
                'filetype:log'
            ],
            "Admin/Login": [
                'inurl:admin',
                'inurl:login',
                'intitle:"Admin Panel"'
            ],
            "Config Files": [
                'inurl:"wp-config.php"',
                'filetype:conf',
                'inurl:config'
            ]
        }

    async def scan(self, target: str):
        self.logger.info(f"Starting focused dorking scan for: {target}")
        findings = []
        stats = {
            "total_dorks": 0,
            "total_results": 0,
            "categories_scanned": 0,
            "errors": 0
        }
        
        for category, dork_list in self.dorks.items():
            self.logger.info(f"Scanning category: {category}")
            stats["categories_scanned"] += 1
            
            for dork in dork_list:
                query = f"site:{target} {dork}"
                stats["total_dorks"] += 1
                self.logger.info(f"Testing: {query}")
                
                try:
                    # Conservative rate limiting with randomization
                    await asyncio.sleep(random.randint(10, 20))
                    # Small chance of longer break
                    if random.random() < 0.05:
                        self.logger.info("Taking a stealth break...")
                        await asyncio.sleep(random.randint(30, 60))
                    results_found = 0
                    
                    for result in search(query, num_results=3):
                        # Determine severity based on category
                        severity = self._get_severity(category)
                        
                        finding = {
                            "type": "Google Dork",
                            "category": category,
                            "severity": severity,
                            "dork": dork,
                            "url": result,
                            "description": f"Found via {category} dork: {dork}",
                            "timestamp": datetime.now().isoformat()
                        }
                        findings.append(finding)
                        results_found += 1
                        stats["total_results"] += 1
                        self.logger.success(f"[{category}] Found: {result}")
                    
                    if results_found == 0:
                        self.logger.info(f"No results for dork: {dork}")
                        
                except Exception as e:
                    stats["errors"] += 1
                    self.logger.error(f"Error with dork '{dork}': {str(e)}")
                    # Add extra delay after error
                    await asyncio.sleep(30)
                    continue
        
        self.logger.info(f"Focused dorking scan completed. Found {stats['total_results']} results from {stats['total_dorks']} dorks")
        
        return {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "findings": findings,
            "stats": stats
        }
    
    def _get_severity(self, category: str) -> str:
        """Determine severity based on dork category"""
        high_risk_categories = ["Critical Files", "Config Files"]
        medium_risk_categories = ["Admin/Login"]
        
        if category in high_risk_categories:
            return "HIGH"
        elif category in medium_risk_categories:
            return "MEDIUM"
        else:
            return "LOW"
