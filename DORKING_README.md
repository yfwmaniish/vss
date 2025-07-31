# Google Dorking Scanner for VSS

## Overview

The Google Dorking functionality has been successfully integrated into the VSS (Vulnerability Scanner & Security Suite). This feature allows you to automatically search for sensitive information, misconfigurations, and exposed files on a target domain using Google search operators (dorks).

## Files Added/Modified

### New Files:
- `scanners/dorking.py` - Full comprehensive dorking scanner with 8 categories
- `scanners/focused_dorking.py` - Focused scanner with essential dorks to avoid rate limiting
- `core/dorking.py` - Core module that integrates dorking into the main scanner
- `run_vss.ps1` - PowerShell wrapper to use the correct Python interpreter

### Modified Files:
- `vss.py` - Added `--dorking` command-line argument and integration
- `requirements.txt` - Added `googlesearch-python>=1.2.0` dependency

## Usage

### Basic Usage
```powershell
# Run dorking scan on a target
.\run_vss.ps1 -t example.com --dorking

# Run dorking with other scans
.\run_vss.ps1 -t example.com --dorking --subdomain --ssl

# Run all scans including dorking
.\run_vss.ps1 -t example.com --all

# Save results to JSON
.\run_vss.ps1 -t example.com --dorking --output results.json --json
```

### Command Line Options
- `--dorking` - Enable Google dorking scan
- `-t TARGET` - Specify target domain
- `--timeout SECONDS` - Set timeout (default: 10 seconds)
- `--output FILE` - Save results to file
- `--json` - Output in JSON format
- `-v` - Verbose output

## Dork Categories

### Focused Scanner (Default)
The focused scanner includes essential dorks to minimize rate limiting:

1. **Critical Files** (HIGH severity)
   - `filetype:env` - Environment files
   - `filetype:sql` - SQL files
   - `inurl:.git` - Git repositories
   - `filetype:log` - Log files

2. **Admin/Login** (MEDIUM severity)
   - `inurl:admin` - Admin pages
   - `inurl:login` - Login pages
   - `intitle:"Admin Panel"` - Admin panels

3. **Config Files** (HIGH severity)
   - `inurl:"wp-config.php"` - WordPress config
   - `filetype:conf` - Configuration files
   - `inurl:config` - Config directories

### Comprehensive Scanner
The full scanner includes 8 categories with 40+ dorks:

1. **Admin Panels** - Administrative interfaces
2. **Sensitive Files** - Files containing sensitive data
3. **Configuration Files** - Application configuration files
4. **Backup Files** - Backup and dump files
5. **Development Files** - Development and debug files
6. **Database Files** - Database-related files
7. **Error Pages** - Error messages that leak information
8. **Login Pages** - Authentication interfaces

## Rate Limiting & Best Practices

### Current Rate Limits
- **Focused Scanner**: 15-second delay between requests
- **Comprehensive Scanner**: 20-second delay between requests
- **Error Recovery**: 30-second delay after errors

### Recommendations
1. Use the focused scanner for regular scans
2. Use the comprehensive scanner for in-depth analysis
3. Avoid running multiple concurrent dorking scans
4. Consider using VPN or rotating IP addresses for large scans
5. Respect Google's Terms of Service

## Examples

### Example 1: Basic Dorking Scan
```powershell
.\run_vss.ps1 -t tesla.com --dorking
```

### Example 2: Dorking with Output
```powershell
.\run_vss.ps1 -t tesla.com --dorking --output tesla_dorks.json --json
```

### Example 3: Full Security Scan
```powershell
.\run_vss.ps1 -t tesla.com --all --output tesla_full_scan.json --json
```

## Output Format

### JSON Structure
```json
{
  "target": "example.com",
  "timestamp": "2025-07-30T12:00:00.000000",
  "scans": {
    "dorking": {
      "target": "example.com",
      "timestamp": "2025-07-30T12:00:00.000000",
      "findings": [
        {
          "type": "Google Dork",
          "category": "Critical Files",
          "severity": "HIGH",
          "dork": "filetype:env",
          "url": "https://example.com/config/.env",
          "description": "Found via Critical Files dork: filetype:env",
          "timestamp": "2025-07-30T12:00:00.000000"
        }
      ],
      "stats": {
        "total_dorks": 10,
        "total_results": 5,
        "categories_scanned": 3,
        "errors": 1
      }
    }
  }
}
```

## Troubleshooting

### Common Issues

1. **"Too Many Requests" Error**
   - Increase delays in the scanner
   - Wait before retrying
   - Use different IP address

2. **"googlesearch-python not available"**
   - Install dependency: `pip install googlesearch-python`
   - Use the correct Python interpreter

3. **No Results Found**
   - Target may not have exposed files
   - Try different dorks manually
   - Check if site is indexed by Google

### Python Environment Issues
If you encounter Python path issues, use the PowerShell wrapper:
```powershell
.\run_vss.ps1 [arguments]
```

This ensures the correct Python 3.10 interpreter is used.

## Security Considerations

1. **Legal Compliance**: Only use on domains you own or have permission to test
2. **Ethical Use**: Respect robots.txt and terms of service
3. **Rate Limiting**: Don't overwhelm Google's servers
4. **Data Handling**: Secure any sensitive information found

## Future Enhancements

Potential improvements for the dorking functionality:

1. **Multiple Search Engines**: Support for Bing, DuckDuckGo
2. **Custom Dork Lists**: User-provided dork files
3. **Proxy Support**: Rotate through proxy servers
4. **Results Validation**: Verify found URLs are accessible
5. **Report Integration**: Enhanced reporting with screenshots

## Contributing

To add new dorks or improve the scanner:

1. Edit `scanners/focused_dorking.py` or `scanners/dorking.py`
2. Add new dorks to appropriate categories
3. Test with small delays to avoid rate limiting
4. Update severity classifications as needed

## Dependencies

- `googlesearch-python>=1.2.0`
- `requests>=2.20`
- `aiohttp>=3.8.0`
- `beautifulsoup4>=4.9.0`
