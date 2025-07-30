#!/usr/bin/env python3
"""
V$$ - Report Generator
Made by Decimal & Vectorindia1 by Team H4$HCR4CK
"""

import json
import os
import sys
import argparse
from datetime import datetime
from typing import Dict, Any, List
import base64
from pathlib import Path

try:
    from jinja2 import Template, Environment, FileSystemLoader
    from weasyprint import HTML, CSS
    import matplotlib.pyplot as plt
    import seaborn as sns
    from matplotlib.patches import Wedge
    import io
    import numpy as np
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Please install: pip install jinja2 weasyprint matplotlib seaborn")
    sys.exit(1)

class VSSReportGenerator:
    def __init__(self):
        self.severity_colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14', 
            'MEDIUM': '#ffc107',
            'LOW': '#28a745',
            'INFO': '#17a2b8'
        }
        
        self.scan_types = {
            's3': 'S3 Bucket Analysis',
            'ftp': 'FTP Service Scan',
            'shodan': 'Shodan Intelligence',
            'dev_endpoints': 'Development Endpoints',
            'subdomain': 'Subdomain Enumeration',
            'port_scan': 'Port & Service Scan',
            'ssl': 'SSL/TLS Analysis',
            'virustotal': 'VirusTotal Intelligence',
            'hibp': 'Have I Been Pwned'
        }

    def load_scan_results(self, json_file: str) -> Dict[str, Any]:
        """Load scan results from JSON file"""
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            raise Exception(f"Failed to load scan results: {e}")

    def generate_charts(self, data: Dict[str, Any]) -> Dict[str, str]:
        """Generate charts for the report"""
        charts = {}
        
        # Severity distribution chart
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        
        for scan_name, scan_data in data.get('scans', {}).items():
            findings = scan_data.get('findings', [])
            for finding in findings:
                severity = finding.get('severity', 'INFO')
                severity_counts[severity] += 1
        
        # Create severity pie chart
        fig, ax = plt.subplots(figsize=(8, 6))
        non_zero_severities = {k: v for k, v in severity_counts.items() if v > 0}
        
        if non_zero_severities:
            colors = [self.severity_colors[sev] for sev in non_zero_severities.keys()]
            wedges, texts, autotexts = ax.pie(
                non_zero_severities.values(),
                labels=non_zero_severities.keys(),
                colors=colors,
                autopct='%1.1f%%',
                startangle=90
            )
            ax.set_title('Findings by Severity', fontsize=14, fontweight='bold')
        else:
            ax.text(0.5, 0.5, 'No findings', ha='center', va='center', transform=ax.transAxes)
            ax.set_title('Findings by Severity', fontsize=14, fontweight='bold')
        
        # Save chart to base64
        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight', dpi=150)
        buf.seek(0)
        charts['severity_chart'] = base64.b64encode(buf.read()).decode()
        plt.close()
        
        # Scan results overview chart
        fig, ax = plt.subplots(figsize=(10, 6))
        scan_results = []
        scan_labels = []
        
        for scan_name, scan_data in data.get('scans', {}).items():
            scan_labels.append(self.scan_types.get(scan_name, scan_name.upper()))
            findings_count = len(scan_data.get('findings', []))
            scan_results.append(findings_count)
        
        if scan_results:
            bars = ax.bar(scan_labels, scan_results, color='#007bff', alpha=0.7)
            ax.set_title('Findings per Scan Type', fontsize=14, fontweight='bold')
            ax.set_ylabel('Number of Findings')
            plt.xticks(rotation=45, ha='right')
            
            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                       f'{int(height)}', ha='center', va='bottom')
        
        # Save chart to base64
        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight', dpi=150)
        buf.seek(0)
        charts['scan_overview_chart'] = base64.b64encode(buf.read()).decode()
        plt.close()
        
        return charts

    def generate_html_report(self, data: Dict[str, Any], output_file: str = None) -> str:
        """Generate HTML report"""
        
        # Generate charts
        charts = self.generate_charts(data)
        
        # HTML template
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>V$$ Security Scan Report - {{ target }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f8f9fa;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            border-radius: 10px;
            margin-bottom: 2rem;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }
        
        .header .subtitle {
            font-size: 1.2rem;
            opacity: 0.9;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .summary-card {
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .summary-card h3 {
            color: #666;
            font-size: 0.9rem;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
        }
        
        .summary-card .value {
            font-size: 2rem;
            font-weight: bold;
            color: #333;
        }
        
        .charts-section {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }
        
        .chart-container {
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .chart-container img {
            max-width: 100%;
            height: auto;
        }
        
        .scan-section {
            background: white;
            margin-bottom: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .scan-header {
            background: #f8f9fa;
            padding: 1rem 1.5rem;
            border-bottom: 1px solid #dee2e6;
        }
        
        .scan-header h2 {
            color: #495057;
            margin-bottom: 0.5rem;
        }
        
        .scan-status {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .status-pass { background: #d4edda; color: #155724; }
        .status-fail { background: #f8d7da; color: #721c24; }
        .status-success { background: #d1ecf1; color: #0c5460; }
        
        .scan-content {
            padding: 1.5rem;
        }
        
        .findings-list {
            list-style: none;
        }
        
        .finding-item {
            background: #f8f9fa;
            margin-bottom: 1rem;
            padding: 1rem;
            border-radius: 6px;
            border-left: 4px solid #dee2e6;
        }
        
        .finding-critical { border-left-color: #dc3545; }
        .finding-high { border-left-color: #fd7e14; }
        .finding-medium { border-left-color: #ffc107; }
        .finding-low { border-left-color: #28a745; }
        .finding-info { border-left-color: #17a2b8; }
        
        .finding-header {
            display: flex;
            justify-content: between;
            align-items: center;
            margin-bottom: 0.5rem;
        }
        
        .finding-type {
            font-weight: bold;
            color: #333;
        }
        
        .severity-badge {
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
            color: white;
            margin-left: auto;
        }
        
        .severity-critical { background: #dc3545; }
        .severity-high { background: #fd7e14; }
        .severity-medium { background: #ffc107; color: #333; }
        .severity-low { background: #28a745; }
        .severity-info { background: #17a2b8; }
        
        .finding-description {
            color: #666;
            margin-top: 0.5rem;
        }
        
        .metadata-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }
        
        .metadata-table th,
        .metadata-table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        
        .metadata-table th {
            background: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }
        
        .footer {
            text-align: center;
            margin-top: 3rem;
            padding: 2rem;
            color: #666;
            border-top: 1px solid #dee2e6;
        }
        
        @media (max-width: 768px) {
            .charts-section {
                grid-template-columns: 1fr;
            }
            
            .summary-cards {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 V$$ Security Scan Report</h1>
            <div class="subtitle">Target: {{ target }} | Generated: {{ timestamp }}</div>
        </div>
        
        <div class="summary-cards">
            <div class="summary-card">
                <h3>Target</h3>
                <div class="value">{{ target }}</div>
            </div>
            <div class="summary-card">
                <h3>Total Scans</h3>
                <div class="value">{{ total_scans }}</div>
            </div>
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="value">{{ total_findings }}</div>
            </div>
            <div class="summary-card">
                <h3>Critical Issues</h3>
                <div class="value" style="color: #dc3545;">{{ critical_findings }}</div>
            </div>
        </div>
        
        <div class="charts-section">
            <div class="chart-container">
                <h3>Findings by Severity</h3>
                <img src="data:image/png;base64,{{ charts.severity_chart }}" alt="Severity Distribution">
            </div>
            <div class="chart-container">
                <h3>Findings per Scan Type</h3>
                <img src="data:image/png;base64,{{ charts.scan_overview_chart }}" alt="Scan Overview">
            </div>
        </div>
        
        {% for scan_name, scan_data in scans.items() %}
        <div class="scan-section">
            <div class="scan-header">
                <h2>{{ scan_types.get(scan_name, scan_name.upper()) }}</h2>
                {% set status = 'success' if scan_data.findings else ('fail' if scan_data.get('pass') == false else 'pass') %}
                <span class="scan-status status-{{ status }}">
                    {% if scan_data.findings %}
                        {{ scan_data.findings|length }} findings
                    {% elif scan_data.get('pass') == false %}
                        Failed
                    {% else %}
                        Passed
                    {% endif %}
                </span>
            </div>
            <div class="scan-content">
                {% if scan_data.findings %}
                    <ul class="findings-list">
                        {% for finding in scan_data.findings %}
                        <li class="finding-item finding-{{ finding.severity.lower() }}">
                            <div class="finding-header">
                                <div class="finding-type">{{ finding.type }}</div>
                                <span class="severity-badge severity-{{ finding.severity.lower() }}">
                                    {{ finding.severity }}
                                </span>
                            </div>
                            <div class="finding-description">{{ finding.description }}</div>
                            {% if finding.get('details') %}
                                <details style="margin-top: 0.5rem;">
                                    <summary style="cursor: pointer; color: #007bff;">Show Details</summary>
                                    <pre style="background: #f8f9fa; padding: 1rem; border-radius: 4px; margin-top: 0.5rem; overflow-x: auto;">{{ finding.details | tojson(indent=2) }}</pre>
                                </details>
                            {% endif %}
                        </li>
                        {% endfor %}
                    </ul>
                {% else %}
                    <p style="color: #28a745; font-weight: 500;">✅ No security issues found in this scan.</p>
                {% endif %}
                
                {% if scan_name == 'ssl' and scan_data.get('certificate') %}
                    <h4 style="margin-top: 2rem; margin-bottom: 1rem;">Certificate Information</h4>
                    <table class="metadata-table">
                        <tr><th>Subject</th><td>{{ scan_data.certificate.subject.get('CN', 'N/A') }}</td></tr>
                        <tr><th>Issuer</th><td>{{ scan_data.certificate.issuer.get('CN', 'N/A') }}</td></tr>
                        <tr><th>Valid From</th><td>{{ scan_data.certificate.not_before }}</td></tr>
                        <tr><th>Valid Until</th><td>{{ scan_data.certificate.not_after }}</td></tr>
                        <tr><th>Signature Algorithm</th><td>{{ scan_data.certificate.signature_algorithm }}</td></tr>
                    </table>
                {% endif %}
                
                {% if scan_name == 'port_scan' and scan_data.get('open_ports') %}
                    <h4 style="margin-top: 2rem; margin-bottom: 1rem;">Open Ports</h4>
                    <table class="metadata-table">
                        <thead>
                            <tr><th>Port</th><th>Service</th><th>Version</th><th>Status</th></tr>
                        </thead>
                        <tbody>
                            {% for port_num in scan_data.open_ports %}
                            {% set port_service = scan_data.services.get(port_num|string, {}) %}
                            <tr>
                                <td>{{ port_num }}</td>
                                <td>{{ port_service.get('service', 'Unknown') }}</td>
                                <td>{{ port_service.get('version', 'Unknown') }}</td>
                                <td>Open</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                {% endif %}
            </div>
        </div>
        {% endfor %}
        
        <div class="footer">
            <p>Generated by V$$ (Vulnerability Scanner & Security Suite) on {{ timestamp }}</p>
            <p>Report contains {{ total_findings }} findings across {{ total_scans }} scan types</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Process data for template
        total_scans = len(data.get('scans', {}))
        total_findings = sum(len(scan.get('findings', [])) for scan in data.get('scans', {}).values())
        critical_findings = sum(1 for scan in data.get('scans', {}).values() 
                              for finding in scan.get('findings', []) 
                              if finding.get('severity') == 'CRITICAL')
        
        # Render template
        template = Template(html_template)
        html_content = template.render(
            target=data.get('target', 'Unknown'),
            timestamp=data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            scans=data.get('scans', {}),
            scan_types=self.scan_types,
            total_scans=total_scans,
            total_findings=total_findings,
            critical_findings=critical_findings,
            charts=charts
        )
        
        # Save HTML file if output specified
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
        
        return html_content

    def generate_pdf_report(self, data: Dict[str, Any], output_file: str):
        """Generate PDF report from HTML"""
        html_content = self.generate_html_report(data)
        
        # CSS for PDF formatting
        pdf_css = CSS(string='''
            @page {
                size: A4;
                margin: 1cm;
            }
            
            body {
                font-size: 12px;
            }
            
            .header h1 {
                font-size: 24px;
            }
            
            .charts-section {
                page-break-inside: avoid;
            }
            
            .scan-section {
                page-break-inside: avoid;
                margin-bottom: 1rem;
            }
            
            .finding-item {
                page-break-inside: avoid;
            }
        ''')
        
        # Generate PDF
        html_doc = HTML(string=html_content)
        html_doc.write_pdf(output_file, stylesheets=[pdf_css])

def main():
    parser = argparse.ArgumentParser(description='Generate HTML/PDF reports from V$$ scan results')
    parser.add_argument('input_file', help='Input JSON file with scan results')
    parser.add_argument('-f', '--format', choices=['html', 'pdf', 'both'], default='both',
                       help='Output format (default: both)')
    parser.add_argument('-o', '--output', help='Output file prefix (default: based on input filename)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input_file):
        print(f"Error: Input file '{args.input_file}' not found")
        sys.exit(1)
    
    # Determine output filename prefix
    if args.output:
        output_prefix = args.output
    else:
        output_prefix = Path(args.input_file).stem + '_report'
    
    # Initialize report generator
    generator = VSSReportGenerator()
    
    try:
        # Load scan results
        print(f"Loading scan results from {args.input_file}...")
        data = generator.load_scan_results(args.input_file)
        
        # Generate reports
        if args.format in ['html', 'both']:
            html_file = f"{output_prefix}.html"
            print(f"Generating HTML report...")
            generator.generate_html_report(data, html_file)
            print(f"✅ HTML report saved to: {html_file}")
        
        if args.format in ['pdf', 'both']:
            pdf_file = f"{output_prefix}.pdf"
            print(f"Generating PDF report...")
            generator.generate_pdf_report(data, pdf_file)
            print(f"✅ PDF report saved to: {pdf_file}")
        
        print("\n🎉 Report generation completed successfully!")
        
    except Exception as e:
        print(f"❌ Error generating report: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
