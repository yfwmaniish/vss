"""
HMS Configuration File
Contains default settings and API key configuration
"""

import os

# Shodan API Configuration
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', 'CfVIImWmMGQnSVamidIibFzCs8wXG5ia')

# Default settings
DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 10
DEFAULT_USER_AGENT = 'HMS/1.0 (Hybrid Misconfiguration Scanner)'

# S3 Configuration
S3_REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
    'ap-south-1', 'ap-southeast-1', 'ap-southeast-2',
    'ap-northeast-1', 'ap-northeast-2', 'sa-east-1'
]

# Common S3 bucket patterns to test
S3_BUCKET_PATTERNS = [
    '{target}',
    '{target}-backup',
    '{target}-backups',
    '{target}-dev',
    '{target}-test',
    '{target}-staging',
    '{target}-prod',
    '{target}-production',
    '{target}-logs',
    '{target}-assets',
    '{target}-data',
    '{target}-files',
    'backup-{target}',
    'dev-{target}',
    'test-{target}',
    'staging-{target}',
    'prod-{target}',
    'logs-{target}',
    'assets-{target}',
    'data-{target}',
    'files-{target}'
]

# FTP Configuration
FTP_DEFAULT_PORT = 21
FTP_ANONYMOUS_USERS = ['anonymous', 'ftp', 'guest']
FTP_TIMEOUT = 10

# JWT Configuration
JWT_COMMON_SECRETS = [
    'secret',
    'password',
    '123456',
    'admin',
    'root',
    'test',
    'key',
    'jwt',
    'token',
    'default',
    'changeme',
    'your-secret-key',
    'your_secret_key',
    'secretkey',
    'mysecret',
    'mykey',
    'supersecret',
    'topsecret',
    'verysecret',
    'jwt-secret',
    'jwt_secret'
]

# Dev Endpoint Configuration
DEFAULT_DEV_ENDPOINTS = [
    '/debug',
    '/test',
    '/admin',
    '/dev',
    '/development',
    '/staging',
    '/phpinfo.php',
    '/info.php',
    '/server-status',
    '/server-info',
    '/status',
    '/health',
    '/healthcheck',
    '/ping',
    '/.env',
    '/config',
    '/configuration',
    '/swagger',
    '/api-docs',
    '/docs',
    '/documentation',
    '/readme',
    '/README',
    '/robots.txt',
    '/sitemap.xml',
    '/.git',
    '/.svn',
    '/.DS_Store',
    '/backup',
    '/backups',
    '/db',
    '/database',
    '/sql',
    '/logs',
    '/log',
    '/temp',
    '/tmp',
    '/uploads',
    '/upload',
    '/files',
    '/file',
    '/private',
    '/secret',
    '/hidden',
    '/console',
    '/shell',
    '/cmd',
    '/terminal',
    '/phpmyadmin',
    '/adminer',
    '/wp-admin',
    '/wp-login.php',
    '/administrator',
    '/management',
    '/manager',
    '/control',
    '/panel',
    '/dashboard',
    '/cpanel',
    '/plesk',
    '/webmail',
    '/mail',
    '/ftp',
    '/ssh',
    '/telnet',
    '/vnc',
    '/rdp'
]

# Risk levels for findings
RISK_LEVELS = {
    'CRITICAL': 'red',
    'HIGH': 'yellow',
    'MEDIUM': 'blue',
    'LOW': 'green',
    'INFO': 'cyan'
}

# Output formatting
MAX_LINE_LENGTH = 80
BANNER_TEXT = """
██╗  ██╗███╗   ███╗███████╗
██║  ██║████╗ ████║██╔════╝
███████║██╔████╔██║███████╗
██╔══██║██║╚██╔╝██║╚════██║
██║  ██║██║ ╚═╝ ██║███████║
╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝

Hybrid Misconfiguration Scanner v1.0
"""
