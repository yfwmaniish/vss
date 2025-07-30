import datetime
import json
import sys

class Logger:
    def __init__(self, verbose=False, quiet=False, json_output=False):
        self.verbose = verbose
        self.quiet = quiet
        self.json_output = json_output

    def print_banner(self):
        if not self.quiet:
            print("""
██╗   ██╗█████╗ █████╗ 
██║   ██║╚══██╗╚══██╗
███╗ ███║█████╔╝█████╔╝
██╔█╗█╔██║╚══██╗╚══██╗
██╔╝█║ ██║█████╔╝█████╔╝
╚═╝ ╚╝ ╚═╝╚════╝ ╚════╝ 

V$$ - Vulnerability Scanner & Security Suite v1.0
Made by Decimal & Vectorindia1 by Team H4$HCR4CK
""")

    def info(self, message):
        if self.verbose or not self.quiet:
            print(f"[INFO] {message}")

    def success(self, message):
        print(f"[SUCCESS] {message}")

    def warning(self, message):
        print(f"[WARNING] {message}")

    def error(self, message):
        print(f"[ERROR] {message}")
        sys.exit(1)

    def get_timestamp(self):
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def print_summary(self, results):
        if not self.quiet:
            print("\n--- Scan Summary ---")
            for scan, result in results['scans'].items():
                # Determine status based on scan type and findings
                if 'pass' in result:
                    # Special handling for dev_endpoints - findings mean successful detection
                    if scan == 'dev_endpoints':
                        if result.get('findings'):
                            status = 'SUCCESS'  # Found exposed endpoints = successful detection
                        else:
                            status = 'PASS'  # No exposed endpoints = clean/passing
                    else:
                        # For other scans with explicit pass/fail (S3, FTP, Shodan)
                        status = 'PASS' if result.get('pass', False) else 'FAIL'
                else:
                    # For info-gathering scans (subdomain, port, SSL, VT)
                    # Success means the scan completed, regardless of findings
                    if 'findings' in result or 'subdomains' in result or 'open_ports' in result:
                        status = 'SUCCESS'
                    elif 'error' in result:
                        status = 'ERROR'
                    else:
                        status = 'COMPLETED'
                
                # Count findings for additional context
                findings_count = len(result.get('findings', []))
                if findings_count > 0:
                    print(f"{scan.upper()}: {status} ({findings_count} findings)")
                else:
                    print(f"{scan.upper()}: {status}")

    def save_results_to_file(self, results, file_path):
        with open(file_path, 'w') as f:
            for scan, result in results['scans'].items():
                f.write(f"{scan.upper()}\n{json.dumps(result, indent=2)}\n\n")
