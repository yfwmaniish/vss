#!/usr/bin/env python3
"""
V$$ - Vulnerability Scanner & Security Suite
Made by Decimal & Vectorindia1 by Team H4$HCR4CK
"""

import argparse
import json
import sys
from pathlib import Path

from core.s3 import S3Scanner
from core.ftp import FTPScanner
from core.devscan import DevEndpointScanner
from core.jwt import JWTScanner
from core.shodan_lookup import ShodanScanner
from scanners.subdomain import SubdomainScanner
from scanners.advanced_port_scanner import AdvancedPortScanner
from scanners.ssl_scanner import SSLScanner
from scanners.virustotal import VirusTotalScanner
from scanners.hibp_scanner import HaveIBeenPwnedScanner
from utils.logger import Logger
import config
import asyncio

try:
    from report_generator import VSSReportGenerator
    REPORT_GENERATOR_AVAILABLE = True
except ImportError:
    REPORT_GENERATOR_AVAILABLE = False

async def run_async_scans(args, logger, results):
    """Run asynchronous scanners"""
    # Dev Endpoint Scanning
    if args.dev or args.all:
        logger.info(f"Starting dev endpoint scan for: {args.target}")
        dev_scanner = DevEndpointScanner(
            logger, 
            timeout=args.timeout, 
            threads=args.threads,
            wordlist_path=args.wordlist
        )
        dev_results = await dev_scanner.scan_target(args.target)
        results['scans']['dev_endpoints'] = dev_results
    
    # Subdomain Enumeration
    if args.subdomain or args.all:
        logger.info(f"Starting subdomain enumeration for: {args.target}")
        subdomain_scanner = SubdomainScanner(timeout=args.timeout)
        subdomain_results = await subdomain_scanner.scan(args.target)
        results['scans']['subdomain'] = subdomain_results
    
    # Advanced Port Scanning with Service Detection
    if args.port_scan or args.all:
        logger.info(f"Starting advanced port scan for: {args.target}")
        port_scanner = AdvancedPortScanner(timeout=5, max_concurrent=50)
        # Scan common ports (1-1024)
        common_ports = list(range(1, 1025))
        port_results = await port_scanner.scan(args.target, common_ports)
        results['scans']['port_scan'] = port_results
    
    # SSL/TLS Analysis
    if args.ssl or args.all:
        logger.info(f"Starting SSL/TLS analysis for: {args.target}")
        ssl_scanner = SSLScanner(timeout=args.timeout)
        ssl_results = await ssl_scanner.scan(args.target)
        results['scans']['ssl'] = ssl_results
    
    # VirusTotal Scan
    if args.virustotal or args.all:
        logger.info(f"Starting VirusTotal scan for: {args.target}")
        vt_api_key = "b446ef20d8a520b0986c316dab9b5f27bf9b40a733a90c9febc8a8a8adde5ca8"
        vt_scanner = VirusTotalScanner(vt_api_key, timeout=args.timeout)
        vt_results = await vt_scanner.scan(args.target)
        results['scans']['virustotal'] = vt_results
    
    # Have I Been Pwned Check
    if args.hibp:
        # For now, we'll skip HIBP since you'll provide the API key later
        logger.warning("Have I Been Pwned scan requested but API key not available yet")
        # hibp_scanner = HaveIBeenPwnedScanner(hibp_api_key)
        # if args.email:
        #     hibp_results = await hibp_scanner.check_email(args.email)
        # else:
        #     hibp_results = await hibp_scanner.check_domain(args.target)
        # results['scans']['hibp'] = hibp_results

def main():
    parser = argparse.ArgumentParser(
        description="V$$ - Vulnerability Scanner & Security Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vss.py -t example.com --all
  python vss.py -t 192.168.1.1 --s3 --ftp
  python vss.py -t mybucket --s3-bucket
  python vss.py --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  python vss.py -t example.com --shodan --api-key YOUR_KEY
  python vss.py -t example.com --all --auto-report
  python vss.py -t example.com --dev --ssl --auto-report --report-format both
        """
    )
    
    # Target options
    parser.add_argument('-t', '--target', 
                       help='Target to scan (IP, domain, URL, or S3 bucket name)')
    parser.add_argument('--jwt', 
                       help='JWT token to analyze')
    
    # Scan modules
    parser.add_argument('--all', action='store_true',
                       help='Run all available scans (requires target)')
    parser.add_argument('--s3', action='store_true',
                       help='Scan for S3 bucket misconfigurations')
    parser.add_argument('--s3-bucket', action='store_true',
                       help='Direct S3 bucket name scan (use with -t)')
    parser.add_argument('--ftp', action='store_true',
                       help='Scan for open/anonymous FTP')
    parser.add_argument('--dev', action='store_true',
                       help='Scan for exposed dev/debug endpoints')
    parser.add_argument('--shodan', action='store_true',
                       help='Lookup target in Shodan (requires API key)')
    parser.add_argument('--subdomain', action='store_true',
                       help='Enumerate subdomains using multiple techniques')
    parser.add_argument('--port-scan', action='store_true',
                       help='Perform port scanning on target')
    parser.add_argument('--ssl', action='store_true',
                       help='Analyze SSL/TLS configuration and certificates')
    parser.add_argument('--virustotal', action='store_true',
                       help='Check URL/domain reputation with VirusTotal')
    parser.add_argument('--hibp', action='store_true',
                       help='Check for data breaches using Have I Been Pwned')
    parser.add_argument('--email',
                       help='Email address to check for breaches (use with --hibp)')
    
    # Configuration
    parser.add_argument('--api-key', 
                       help='Shodan API key (or set SHODAN_API_KEY env var)')
    parser.add_argument('--wordlist', 
                       help='Custom wordlist for dev endpoint scanning')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('--threads', type=int, default=10,
                       help='Number of concurrent threads (default: 10)')
    
    # Output options
    parser.add_argument('-o', '--output', 
                       help='Save results to file')
    parser.add_argument('--json', action='store_true',
                       help='Output results in JSON format')
    parser.add_argument('--auto-report', action='store_true',
                       help='Automatically generate PDF report after scan')
    parser.add_argument('--report-format', choices=['html', 'pdf', 'both'], default='pdf',
                       help='Report format for auto-report (default: pdf)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--quiet', action='store_true',
                       help='Suppress banner and non-essential output')
    
    args = parser.parse_args()
    
    # Initialize logger
    logger = Logger(verbose=args.verbose, quiet=args.quiet, json_output=args.json)
    
    if not args.quiet:
        logger.print_banner()
    
    # Validate arguments
    if not args.target and not args.jwt:
        logger.error("Either --target or --jwt must be specified")
        parser.print_help()
        sys.exit(1)
    
    if args.all and not args.target:
        logger.error("--all requires a target to be specified")
        sys.exit(1)
    
    # Initialize results storage
    results = {
        'target': args.target,
        'timestamp': logger.get_timestamp(),
        'scans': {}
    }
    
    try:
        # JWT Analysis
        if args.jwt:
            logger.info("Starting JWT analysis...")
            jwt_scanner = JWTScanner(logger)
            jwt_results = jwt_scanner.analyze_token(args.jwt)
            results['scans']['jwt'] = jwt_results
        
        # Target-based scans
        if args.target:
            # S3 Bucket Scanning
            if args.s3 or args.s3_bucket or args.all:
                logger.info(f"Starting S3 bucket scan for: {args.target}")
                s3_scanner = S3Scanner(logger, timeout=args.timeout)
                if args.s3_bucket:
                    s3_results = s3_scanner.scan_bucket_direct(args.target)
                else:
                    s3_results = s3_scanner.scan_target(args.target)
                results['scans']['s3'] = s3_results
            
            # FTP Scanning
            if args.ftp or args.all:
                logger.info(f"Starting FTP scan for: {args.target}")
                ftp_scanner = FTPScanner(logger, timeout=args.timeout)
                ftp_results = ftp_scanner.scan_target(args.target)
                results['scans']['ftp'] = ftp_results
            
            # Dev Endpoint Scanning (moved to async section)
            # This will be handled in the async function
            
            # Shodan Lookup
            if args.shodan or args.all:
                api_key = args.api_key or config.SHODAN_API_KEY
                if not api_key:
                    logger.warning("Shodan scan requested but no API key provided")
                else:
                    logger.info(f"Starting Shodan lookup for: {args.target}")
                    shodan_scanner = ShodanScanner(logger, api_key)
                    shodan_results = shodan_scanner.lookup_target(args.target)
                    results['scans']['shodan'] = shodan_results
            
            # Run async scanners if any are requested
            async_scan_needed = any([
                args.dev, args.subdomain, args.port_scan, args.ssl, args.virustotal, args.hibp, args.all
            ])
            
            if async_scan_needed:
                asyncio.run(run_async_scans(args, logger, results))
        
        # Output results
        if args.output:
            output_path = Path(args.output)
            if args.json:
                with open(output_path, 'w') as f:
                    json.dump(results, f, indent=2)
                logger.success(f"Results saved to: {output_path}")
            else:
                logger.save_results_to_file(results, output_path)
        
        if args.json and not args.output:
            print(json.dumps(results, indent=2))

        logger.print_summary(results)

        # Auto-generate report
        if args.auto_report:
            if not REPORT_GENERATOR_AVAILABLE:
                logger.warning("Report generator not available. Please install dependencies.")
                return

            logger.info("Generating scan report...")
            report_generator = VSSReportGenerator()
            output_prefix = f"{Path(args.output).stem if args.output else args.target}_report"

            if args.report_format in ['html', 'both']:
                html_file = f"{output_prefix}.html"
                report_generator.generate_html_report(results, html_file)
                logger.success(f"HTML report saved to: {html_file}")

            if args.report_format in ['pdf', 'both']:
                pdf_file = f"{output_prefix}.pdf"
                report_generator.generate_pdf_report(results, pdf_file)
                logger.success(f"PDF report saved to: {pdf_file}")
        
    except KeyboardInterrupt:
        logger.warning("\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
