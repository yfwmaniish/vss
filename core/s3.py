"""
S3 Bucket Scanner Module
Detects publicly accessible S3 buckets and misconfigurations
"""

import requests
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
import json
import re
import config

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


class S3Scanner:
    def __init__(self, logger, timeout=10):
        self.logger = logger
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.DEFAULT_USER_AGENT})

    def scan_target(self, target):
        """Scan a target for potential S3 bucket patterns"""
        results = {
            'target': target,
            'timestamp': self.logger.get_timestamp(),
            'buckets_found': [],
            'pass': True,
            'findings': []
        }

        # Extract domain name for bucket pattern generation
        if target.startswith(('http://', 'https://')):
            domain = urlparse(target).netloc
        else:
            domain = target

        # Remove subdomains for pattern generation
        domain_parts = domain.split('.')
        if len(domain_parts) > 2:
            base_domain = '.'.join(domain_parts[-2:])
            company_name = domain_parts[-2]
        else:
            base_domain = domain
            company_name = domain_parts[0] if domain_parts else target

        # Generate bucket name patterns
        bucket_patterns = []
        for pattern in config.S3_BUCKET_PATTERNS:
            bucket_patterns.append(pattern.format(target=company_name.lower()))

        self.logger.info(f"Testing {len(bucket_patterns)} bucket patterns...")

        for bucket_name in bucket_patterns:
            bucket_result = self._scan_bucket(bucket_name)
            if bucket_result:
                results['buckets_found'].append(bucket_result)
                results['pass'] = False
                results['findings'].append({
                    'type': 'Public S3 Bucket',
                    'severity': 'HIGH',
                    'bucket': bucket_name,
                    'details': bucket_result
                })

        return results

    def scan_bucket_direct(self, bucket_name):
        """Directly scan a specific S3 bucket name"""
        results = {
            'target': bucket_name,
            'timestamp': self.logger.get_timestamp(),
            'buckets_found': [],
            'pass': True,
            'findings': []
        }

        bucket_result = self._scan_bucket(bucket_name)
        if bucket_result:
            results['buckets_found'].append(bucket_result)
            results['pass'] = False
            results['findings'].append({
                'type': 'Public S3 Bucket',
                'severity': 'HIGH',
                'bucket': bucket_name,
                'details': bucket_result
            })

        return results

    def _scan_bucket(self, bucket_name):
        """Scan a specific S3 bucket for public access"""
        self.logger.info(f"Checking bucket: {bucket_name}")
        
        bucket_info = {
            'name': bucket_name,
            'accessible': False,
            'listable': False,
            'writable': False,
            'region': None,
            'objects': [],
            'urls_tested': []
        }

        # Test different S3 URL formats
        urls_to_test = [
            f"https://{bucket_name}.s3.amazonaws.com/",
            f"https://s3.amazonaws.com/{bucket_name}/",
            f"http://{bucket_name}.s3.amazonaws.com/",
            f"http://s3.amazonaws.com/{bucket_name}/"
        ]

        # Test regional endpoints
        for region in config.S3_REGIONS[:5]:  # Test first 5 regions to avoid timeout
            urls_to_test.extend([
                f"https://{bucket_name}.s3.{region}.amazonaws.com/",
                f"https://s3.{region}.amazonaws.com/{bucket_name}/"
            ])

        for url in urls_to_test:
            try:
                bucket_info['urls_tested'].append(url)
                response = self._make_request(url)
                
                if response and response.status_code == 200:
                    bucket_info['accessible'] = True
                    
                    # Try to parse XML response for bucket listing
                    try:
                        root = ET.fromstring(response.text)
                        if root.tag.endswith('ListBucketResult'):
                            bucket_info['listable'] = True
                            
                            # Extract bucket information
                            name_elem = root.find('.//{http://s3.amazonaws.com/doc/2006-03-01/}Name')
                            if name_elem is not None:
                                bucket_info['name'] = name_elem.text
                            
                            # Extract objects
                            for contents in root.findall('.//{http://s3.amazonaws.com/doc/2006-03-01/}Contents'):
                                key_elem = contents.find('.//{http://s3.amazonaws.com/doc/2006-03-01/}Key')
                                size_elem = contents.find('.//{http://s3.amazonaws.com/doc/2006-03-01/}Size')
                                modified_elem = contents.find('.//{http://s3.amazonaws.com/doc/2006-03-01/}LastModified')
                                
                                if key_elem is not None:
                                    obj_info = {
                                        'key': key_elem.text,
                                        'size': size_elem.text if size_elem is not None else 'Unknown',
                                        'last_modified': modified_elem.text if modified_elem is not None else 'Unknown'
                                    }
                                    bucket_info['objects'].append(obj_info)
                    except ET.ParseError:
                        # Not XML, might be HTML error page or other content
                        if 'bucket' in response.text.lower() or 's3' in response.text.lower():
                            bucket_info['accessible'] = True
                    
                    # Test for write permissions
                    bucket_info['writable'] = self._test_write_permissions(url)
                    
                    self.logger.success(f"Found accessible bucket: {bucket_name}")
                    return bucket_info
                    
                elif response and response.status_code == 403:
                    # Bucket exists but access denied
                    bucket_info['accessible'] = False
                    if 'NoSuchBucket' not in response.text:
                        self.logger.info(f"Bucket exists but access denied: {bucket_name}")
                        return bucket_info

            except Exception as e:
                self.logger.info(f"Error testing {url}: {str(e)}")
                continue

        return None

    def _test_write_permissions(self, bucket_url):
        """Test if the bucket allows write operations"""
        try:
            # Try to upload a small test file
            test_key = "hms-test-file.txt"
            test_content = "HMS security scan test"
            
            put_url = f"{bucket_url.rstrip('/')}/{test_key}"
            response = self._make_request(put_url, method='PUT', data=test_content)
            
            if response and response.status_code in [200, 201]:
                # Try to delete the test file
                self._make_request(put_url, method='DELETE')
                return True
                
        except Exception:
            pass
        
        return False

    def _scan_bucket_with_aws_sdk(self, bucket_name):
        """Advanced S3 bucket scanning using AWS SDK"""
        if not BOTO3_AVAILABLE:
            self.logger.info("boto3 not available, skipping AWS SDK checks")
            return None
            
        try:
            # Try anonymous access first
            s3_client = boto3.client('s3', 
                                   aws_access_key_id='',
                                   aws_secret_access_key='',
                                   region_name='us-east-1')
            
            bucket_info = {
                'name': bucket_name,
                'accessible': False,
                'listable': False,
                'writable': False,
                'region': None,
                'acl_public_read': False,
                'acl_public_write': False,
                'bucket_policy': None,
                'encryption': None,
                'versioning': None,
                'objects': []
            }
            
            # Check bucket location
            try:
                location = s3_client.get_bucket_location(Bucket=bucket_name)
                bucket_info['region'] = location.get('LocationConstraint', 'us-east-1')
                bucket_info['accessible'] = True
                self.logger.success(f"Found bucket {bucket_name} in region {bucket_info['region']}")
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'NoSuchBucket':
                    return None
                elif error_code == 'AccessDenied':
                    bucket_info['accessible'] = False
                    return bucket_info
                    
            # Check ACL permissions
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    permission = grant.get('Permission')
                    
                    if grantee.get('Type') == 'Group' and 'AllUsers' in grantee.get('URI', ''):
                        if permission == 'READ':
                            bucket_info['acl_public_read'] = True
                        elif permission == 'WRITE':
                            bucket_info['acl_public_write'] = True
                            
            except ClientError:
                pass
                
            # Check bucket policy
            try:
                policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                bucket_info['bucket_policy'] = json.loads(policy['Policy'])
                # Analyze policy for public access
                if self._analyze_bucket_policy(bucket_info['bucket_policy']):
                    bucket_info['policy_allows_public'] = True
            except ClientError:
                pass
                
            # Check encryption
            try:
                encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                bucket_info['encryption'] = encryption
            except ClientError:
                bucket_info['encryption'] = 'Not configured'
                
            # Check versioning
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                bucket_info['versioning'] = versioning.get('Status', 'Disabled')
            except ClientError:
                pass
                
            # List objects if accessible
            if bucket_info['accessible']:
                try:
                    response = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=10)
                    bucket_info['listable'] = True
                    for obj in response.get('Contents', []):
                        bucket_info['objects'].append({
                            'key': obj['Key'],
                            'size': obj['Size'],
                            'last_modified': obj['LastModified'].isoformat()
                        })
                except ClientError:
                    pass
                    
            return bucket_info
            
        except NoCredentialsError:
            self.logger.info("No AWS credentials configured, skipping SDK checks")
            return None
        except Exception as e:
            self.logger.info(f"AWS SDK error for bucket {bucket_name}: {str(e)}")
            return None
            
    def _analyze_bucket_policy(self, policy):
        """Analyze bucket policy for public access"""
        try:
            for statement in policy.get('Statement', []):
                if (statement.get('Effect') == 'Allow' and 
                    ('*' in str(statement.get('Principal')) or 
                     statement.get('Principal') == '*')):
                    return True
        except Exception:
            pass
        return False
        
    def _check_cloudfront_distribution(self, bucket_name):
        """Check for CloudFront distributions serving this bucket"""
        if not BOTO3_AVAILABLE:
            return None
            
        try:
            cloudfront = boto3.client('cloudfront')
            paginator = cloudfront.get_paginator('list_distributions')
            
            for page in paginator.paginate():
                for dist in page.get('DistributionList', {}).get('Items', []):
                    for origin in dist.get('Origins', {}).get('Items', []):
                        if bucket_name in origin.get('DomainName', ''):
                            return {
                                'distribution_id': dist['Id'],
                                'domain_name': dist['DomainName'],
                                'status': dist['Status'],
                                'origin': origin['DomainName']
                            }
        except Exception as e:
            self.logger.info(f"CloudFront check failed: {str(e)}")
            
        return None

    def _make_request(self, url, method='GET', data=None):
        """Make HTTP request with error handling"""
        try:
            if method == 'GET':
                response = self.session.get(url, timeout=self.timeout)
            elif method == 'PUT':
                response = self.session.put(url, data=data, timeout=self.timeout)
            elif method == 'DELETE':
                response = self.session.delete(url, timeout=self.timeout)
            else:
                return None
            
            return response
            
        except requests.exceptions.RequestException as e:
            self.logger.info(f"Request failed for {url}: {str(e)}")
            return None
