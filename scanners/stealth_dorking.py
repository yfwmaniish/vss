import asyncio
from googlesearch import search
from utils.logger import Logger
import time
import random
from datetime import datetime
from core.dorks_database import DORKS_DATABASE

class StealthDorkingScanner:
    """
    Advanced stealth dorking scanner with anti-detection measures
    """
    
    def __init__(self, logger: Logger, timeout: int = 10):
        self.logger = logger
        self.timeout = timeout
        self.dorks = DORKS_DATABASE
        self.request_count = 0
        self.start_time = time.time()

    async def scan(self, target: str):
        self.logger.info(f"Starting stealth dorking scan for: {target}")
        self.logger.info("Using advanced anti-detection measures...")
        
        findings = []
        stats = {
            "total_dorks": 0,
            "total_results": 0,
            "categories_scanned": 0,
            "errors": 0,
            "stealth_breaks": 0
        }
        
        # Randomize the order of categories to avoid patterns
        categories = list(self.dorks.items())
        random.shuffle(categories)
        
        for category, dork_list in categories:
            # Skip dummy categories in stealth mode
            if category.startswith("Category "):
                continue
                
            self.logger.info(f"Scanning category: {category}")
            stats["categories_scanned"] += 1
            
            # Randomize dork order within category
            shuffled_dorks = list(dork_list)
            random.shuffle(shuffled_dorks)
            
            for dork in shuffled_dorks:
                query = f"site:{target} {dork}"
                stats["total_dorks"] += 1
                self.request_count += 1
                
                try:
                    # Advanced stealth delay calculation
                    delay = await self._calculate_stealth_delay()
                    self.logger.info(f"Waiting {delay}s before next request...")
                    await asyncio.sleep(delay)
                    
                    results_found = 0
                    
                    # Use fewer results per query to be more subtle
                    for result in search(query, num_results=2):
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
                        
                    # Check if we need a long stealth break
                    if await self._needs_stealth_break():
                        break_time = random.randint(180, 360)  # 3-6 minutes
                        stats["stealth_breaks"] += 1
                        self.logger.info(f"Taking extended stealth break for {break_time//60} minutes...")
                        await asyncio.sleep(break_time)
                        
                except Exception as e:
                    stats["errors"] += 1
                    self.logger.error(f"Error with dork '{dork}': {str(e)}")
                    
                    # If we get blocked, take a very long break
                    if "429" in str(e) or "blocked" in str(e).lower():
                        self.logger.warning("Detected rate limiting! Taking emergency break...")
                        await asyncio.sleep(random.randint(300, 600))  # 5-10 minutes
                    else:
                        await asyncio.sleep(random.randint(45, 90))
                    continue
        
        self.logger.info(f"Stealth dorking scan completed. Found {stats['total_results']} results from {stats['total_dorks']} dorks")
        self.logger.info(f"Took {stats['stealth_breaks']} stealth breaks during scan")
        
        return {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "findings": findings,
            "stats": stats
        }
    
    async def _calculate_stealth_delay(self):
        """Calculate dynamic delay based on various factors"""
        base_delay = random.randint(15, 30)
        
        # Increase delay based on request count
        if self.request_count > 20:
            base_delay += random.randint(10, 20)
        
        if self.request_count > 50:
            base_delay += random.randint(15, 30)
            
        # Add time-based variation (slower during peak hours)
        current_hour = datetime.now().hour
        if 9 <= current_hour <= 17:  # Business hours
            base_delay += random.randint(5, 15)
        
        # Random jitter to avoid patterns
        jitter = random.uniform(0.5, 2.0)
        
        return int(base_delay * jitter)
    
    async def _needs_stealth_break(self):
        """Determine if we need a long stealth break"""
        # Take break every 15-25 requests
        if self.request_count % random.randint(15, 25) == 0:
            return True
        
        # Take break after running for 30-45 minutes
        elapsed = time.time() - self.start_time
        if elapsed > random.randint(1800, 2700):  # 30-45 minutes
            self.start_time = time.time()  # Reset timer
            return True
            
        return False
    
    def _get_severity(self, category: str) -> str:
        """Determine severity based on dork category"""
        high_risk_categories = [
            "Files Containing Passwords", "SSH and FTP Files", "API Keys and Tokens",
            "Database Files and Errors", "Configuration Files", 
            "Cloud Storage"
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
