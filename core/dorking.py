import asyncio
from scanners.focused_dorking import FocusedDorkingScanner
from scanners.dorking import DorkingScanner
from scanners.stealth_dorking import StealthDorkingScanner
from utils.logger import Logger

class DorkingModule:
    def __init__(self, logger: Logger, timeout: int = 10, comprehensive: bool = False, stealth: bool = False):
        self.logger = logger
        if stealth:
            self.scanner = StealthDorkingScanner(logger, timeout)
            self.logger.info("Using stealth dorking scanner with advanced anti-detection")
        elif comprehensive:
            self.scanner = DorkingScanner(logger, timeout)
            self.logger.info("Using comprehensive dorking scanner with full database")
        else:
            self.scanner = FocusedDorkingScanner(logger, timeout)
            self.logger.info("Using focused dorking scanner for faster results")

    async def scan(self, target: str):
        self.logger.info(f"Running dorking scan on {target}")
        return await self.scanner.scan(target)

