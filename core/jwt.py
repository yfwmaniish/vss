"""
JWT Vulnerability Scanner Module
Analyzes JWT tokens for common vulnerabilities
"""

import json
import base64
import hmac
import hashlib
import config


class JWTScanner:
    def __init__(self, logger):
        self.logger = logger

    def analyze_token(self, token):
        """Analyze JWT token for vulnerabilities"""
        results = {
            'token': token[:50] + "..." if len(token) > 50 else token,
            'timestamp': self.logger.get_timestamp(),
            'vulnerabilities': [],
            'pass': True,
            'findings': []
        }

        self.logger.info("Starting JWT token analysis...")

        try:
            # Split JWT into components
            parts = token.split('.')
            if len(parts) != 3:
                results['pass'] = False
                results['findings'].append({
                    'type': 'Invalid JWT Format',
                    'severity': 'HIGH',
                    'description': 'JWT token does not have 3 parts separated by dots'
                })
                return results

            header_b64, payload_b64, signature_b64 = parts

            # Decode header
            try:
                header_json = self._decode_base64_url(header_b64)
                header = json.loads(header_json)
                results['header'] = header
                self.logger.success("JWT header decoded successfully")
            except Exception as e:
                results['pass'] = False
                results['findings'].append({
                    'type': 'Invalid JWT Header',
                    'severity': 'HIGH',
                    'description': f'Failed to decode JWT header: {str(e)}'
                })
                return results

            # Decode payload
            try:
                payload_json = self._decode_base64_url(payload_b64)
                payload = json.loads(payload_json)
                results['payload'] = payload
                self.logger.success("JWT payload decoded successfully")
            except Exception as e:
                results['pass'] = False
                results['findings'].append({
                    'type': 'Invalid JWT Payload',
                    'severity': 'HIGH',
                    'description': f'Failed to decode JWT payload: {str(e)}'
                })
                return results

            # Check for algorithm vulnerabilities
            self._check_algorithm_vulnerabilities(header, results)

            # Check for weak secrets (if HMAC algorithm)
            if header.get('alg', '').startswith('HS'):
                self._check_weak_secrets(token, header, results)

            # Check payload claims
            self._check_payload_claims(payload, results)

            # Check for signature verification bypass
            self._check_signature_bypass(token, results)

        except Exception as e:
            results['pass'] = False
            results['findings'].append({
                'type': 'JWT Analysis Error',
                'severity': 'MEDIUM',
                'description': f'Error during JWT analysis: {str(e)}'
            })

        return results

    def _decode_base64_url(self, data):
        """Decode base64url encoded data"""
        # Add padding if needed
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        
        return base64.urlsafe_b64decode(data).decode('utf-8')

    def _check_algorithm_vulnerabilities(self, header, results):
        """Check for algorithm-related vulnerabilities"""
        alg = header.get('alg', '').lower()

        # Check for 'none' algorithm
        if alg == 'none':
            results['pass'] = False
            results['vulnerabilities'].append('none_algorithm')
            results['findings'].append({
                'type': 'None Algorithm Vulnerability',
                'severity': 'CRITICAL',
                'description': 'JWT uses "none" algorithm, allowing signature bypass'
            })
            self.logger.success("CRITICAL: None algorithm vulnerability detected!")

        # Check for weak algorithms
        weak_algorithms = ['hs256', 'hs384', 'hs512']
        if alg in weak_algorithms:
            results['vulnerabilities'].append('weak_algorithm')
            results['findings'].append({
                'type': 'Potentially Weak Algorithm',
                'severity': 'MEDIUM',
                'description': f'JWT uses HMAC algorithm ({alg.upper()}) which may be vulnerable to brute force attacks'
            })

        # Check for algorithm confusion (RS256 vs HS256)
        if alg.startswith('rs'):
            results['findings'].append({
                'type': 'Algorithm Confusion Risk',
                'severity': 'LOW',
                'description': 'JWT uses RSA algorithm - verify server properly validates algorithm to prevent confusion attacks'
            })

    def _check_weak_secrets(self, token, header, results):
        """Check for weak HMAC secrets"""
        self.logger.info("Testing JWT against common weak secrets...")
        
        # Get the parts for re-signing
        parts = token.split('.')
        header_payload = f"{parts[0]}.{parts[1]}"
        
        algorithm = header.get('alg', '').upper()
        
        # Map algorithm to hashlib function
        hash_functions = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512
        }
        
        if algorithm not in hash_functions:
            return
        
        hash_func = hash_functions[algorithm]
        
        for secret in config.JWT_COMMON_SECRETS:
            try:
                # Create signature with weak secret
                signature = hmac.new(
                    secret.encode('utf-8'),
                    header_payload.encode('utf-8'),
                    hash_func
                ).digest()
                
                # Encode signature
                signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
                
                # Compare with original signature
                if signature_b64 == parts[2]:
                    results['pass'] = False
                    results['vulnerabilities'].append('weak_secret')
                    results['findings'].append({
                        'type': 'Weak JWT Secret',
                        'severity': 'CRITICAL',
                        'description': f'JWT signed with weak secret: "{secret}"'
                    })
                    self.logger.success(f"CRITICAL: Weak secret found: {secret}")
                    return
                    
            except Exception:
                continue

    def _check_payload_claims(self, payload, results):
        """Check JWT payload claims for security issues"""
        
        # Check for missing essential claims
        essential_claims = ['iss', 'sub', 'aud', 'exp', 'iat']
        missing_claims = [claim for claim in essential_claims if claim not in payload]
        
        if missing_claims:
            results['findings'].append({
                'type': 'Missing Essential Claims',
                'severity': 'LOW',
                'description': f'JWT missing recommended claims: {", ".join(missing_claims)}'
            })

        # Check expiration
        if 'exp' in payload:
            import time
            current_time = int(time.time())
            exp_time = payload['exp']
            
            if exp_time < current_time:
                results['pass'] = False
                results['vulnerabilities'].append('expired_token')
                results['findings'].append({
                    'type': 'Expired Token',
                    'severity': 'HIGH',
                    'description': 'JWT token has expired'
                })
        else:
            results['findings'].append({
                'type': 'No Expiration',
                'severity': 'MEDIUM',
                'description': 'JWT token has no expiration time (exp claim)'
            })

        # Check for sensitive information in payload
        sensitive_keys = ['password', 'secret', 'key', 'token', 'api_key', 'private']
        found_sensitive = []
        
        def check_sensitive_recursive(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    if any(sensitive in key.lower() for sensitive in sensitive_keys):
                        found_sensitive.append(current_path)
                    check_sensitive_recursive(value, current_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_sensitive_recursive(item, f"{path}[{i}]")

        check_sensitive_recursive(payload)
        
        if found_sensitive:
            results['findings'].append({
                'type': 'Sensitive Information in Payload',
                'severity': 'MEDIUM',
                'description': f'Potentially sensitive keys found: {", ".join(found_sensitive)}'
            })

    def _check_signature_bypass(self, token, results):
        """Check for signature verification bypass techniques"""
        
        # Test empty signature
        parts = token.split('.')
        empty_sig_token = f"{parts[0]}.{parts[1]}."
        
        results['findings'].append({
            'type': 'Signature Bypass Test',
            'severity': 'INFO',
            'description': f'Test empty signature: {empty_sig_token}'
        })

        # Test removing signature entirely
        no_sig_token = f"{parts[0]}.{parts[1]}"
        
        results['findings'].append({
            'type': 'Signature Bypass Test',
            'severity': 'INFO',
            'description': f'Test no signature: {no_sig_token}'
        })
