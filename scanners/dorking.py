import asyncio
from googlesearch import search
from utils.logger import Logger
import time
import random
from datetime import datetime
from core.dorks_database import DORKS_DATABASE

class DorkingScanner:
    def __init__(self, logger: Logger, timeout: int = 10):
        self.logger = logger
        self.timeout = timeout
        self.dorks = DORKS_DATABASE

    async def scan(self, target: str):
        self.logger.info(f"Starting comprehensive dorking scan for: {target}")
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
                
                try:
                    # Rate limiting to avoid getting blocked
# Wait a random time between 12 to 26 seconds to simulate human behavior
                    await asyncio.sleep(random.randint(12, 26))
                    # Occasionally take a long break to further avoid detection
                    if random.random() < 0.08:
                        self.logger.info("Taking a long random break for stealth...")
                        await asyncio.sleep(random.randint(60, 120))
                    results_found = 0
                    
                    for result in search(query, num_results=5):
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
                    # Continue with next dork instead of failing completely
                    continue
        
        self.logger.info(f"Dorking scan completed. Found {stats['total_results']} results from {stats['total_dorks']} dorks")
        
        return {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "findings": findings,
            "stats": stats
        }
    
    def _get_severity(self, category: str) -> str:
        """Determine severity based on dork category"""
        high_risk_categories = [
            "Files Containing Passwords", "SSH and FTP Files", "API Keys and Tokens",
            "Database Files and Errors", "Configuration Files", "Directory Traversal",
            "Exposed Source Code", "Vulnerability Files", "Cloud Storage"
        ]
        medium_risk_categories = [
            "Footholds", "Files Containing Usernames", "Juicy Information",
            "Log and Backup Files", "Exposed Documents and Data", "Network and Firewall Data",
            "Sensitive GET Parameters", "Exposed Error Messages", "Code Sharing Platforms"
        ]
        
        if category in high_risk_categories:
            return "HIGH"
        elif category in medium_risk_categories:
            return "MEDIUM"
        else:
            return "LOW"

