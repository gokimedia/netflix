#!/usr/bin/env python3
"""
Differential Hunter v2.0
Safe differential analysis for response changes and exposure signals.

Techniques:
1. Header Differential - Compare benign header variations
2. Param Differential - Compare benign parameter toggles
3. Timing Differential - Response timing variance tracking
4. Error Differential - Error message variations (benign inputs)
5. GraphQL Differential - Baseline schema availability (optional)

Author: Security Research Team
"""

import requests
import json
import re
import os
import sys
import time
import hashlib
import difflib
from urllib.parse import urlparse, urljoin, urlencode
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Set, Any, Optional, Tuple
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
urllib3.disable_warnings()

from security_checks import evaluate_security_headers, summarize_findings


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
class DiffConfig:
    timeout: int = 15
    concurrency: int = 8
    delay: float = 0.2
    threshold: float = 0.1  # 10% difference is significant
    max_endpoints: int = 50
    max_response_bytes: int = 2_000_000
    max_text_lines: int = 100
    retries: int = 2
    backoff_factor: float = 0.3
    verify_ssl: bool = False
    no_color: bool = False
    allow_graphql_introspection: bool = False
    verbose: bool = False
    output_dir: str = "diff_analysis"
    allowed_hosts: List[str] = field(default_factory=list)
    allowed_suffixes: List[str] = field(default_factory=list)


class DifferentialHunter:
    def __init__(self, target: str, config: DiffConfig = None):
        self.target = target.rstrip('/')
        self.config = config or DiffConfig()
        self.hostname = urlparse(target).netloc
        self.allowed_hosts = {h.lower() for h in self.config.allowed_hosts}
        self.allowed_suffixes = {
            s.lower() if s.startswith(".") else f".{s.lower()}"
            for s in self.config.allowed_suffixes
        }

        self.session = self._build_session()
        self.request_count = 0
        self.security_findings: List[Dict] = []

        self.findings: List[Dict] = []
        self.baseline_responses: Dict[str, Dict] = {}

        # Output
        self.output_path = os.path.join(self.config.output_dir, self.hostname)
        os.makedirs(self.output_path, exist_ok=True)

    def log(self, level: str, msg: str):
        if self.config.no_color or not sys.stdout.isatty():
            prefix = f"[{level.upper()}]"
        else:
            colors = {
                'info': Colors.BLUE,
                'success': Colors.GREEN,
                'warning': Colors.YELLOW,
                'critical': Colors.RED,
                'diff': Colors.PURPLE,
                'found': Colors.CYAN,
            }
            prefix = f"{colors.get(level, '')}[{level.upper()}]{Colors.END}"
        print(f"{prefix} {msg}")

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=self.config.retries,
            backoff_factor=self.config.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD", "POST"],
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
        }
        session.verify = self.config.verify_ssl
        return session

    def _throttle(self):
        if self.config.delay <= 0:
            return
        time.sleep(self.config.delay)

    def _is_allowed_url(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return False
        if self.allowed_hosts or self.allowed_suffixes:
            if host in self.allowed_hosts:
                return True
            return any(host.endswith(suffix) for suffix in self.allowed_suffixes)
        return host == (urlparse(self.target).hostname or "").lower()

    def add_finding(self, title: str, severity: str, details: dict):
        finding = {
            'title': title,
            'severity': severity,
            'timestamp': datetime.now().isoformat(),
            **details
        }
        self.findings.append(finding)
        self.log('found' if severity != 'CRITICAL' else 'critical', f"[{severity}] {title}")

    def _request(self, url: str, method: str = 'GET', **kwargs) -> Tuple[Optional[requests.Response], float]:
        """Make request and return response + timing"""
        if not self._is_allowed_url(url):
            if self.config.verbose:
                self.log('warning', f"Blocked by scope: {url}")
            return None, 0
        kwargs.setdefault('timeout', self.config.timeout)
        self._throttle()
        try:
            start = time.time()
            resp = self.session.request(method, url, stream=True, **kwargs)
            duration = time.time() - start
            self.request_count += 1

            content = b""
            for chunk in resp.iter_content(chunk_size=8192):
                content += chunk
                if len(content) >= self.config.max_response_bytes:
                    break
            resp._content = content

            return resp, duration
        except Exception:
            return None, 0

    def _normalize_response(self, resp: requests.Response) -> Dict:
        """Normalize response for comparison"""
        if not resp:
            return {}

        # Remove dynamic content
        content = resp.text
        # Remove timestamps, nonces, tokens
        content = re.sub(r'\b\d{10,13}\b', 'TIMESTAMP', content)  # Unix timestamps
        content = re.sub(r'[a-f0-9]{32,}', 'HASH', content)  # Hashes
        content = re.sub(r'nonce="[^"]+"', 'nonce="NONCE"', content)
        content = re.sub(r'csrf[^"]*"[^"]+"', 'csrf="TOKEN"', content)

        lines = content.split("\n")
        content_preview = "\n".join(lines[:self.config.max_text_lines])
        return {
            'status': resp.status_code,
            'headers': dict(resp.headers),
            'content_length': len(resp.text),
            'content_hash': hashlib.md5(content.encode()).hexdigest(),
            'content': content_preview,
        }

    def _calculate_diff(self, r1: Dict, r2: Dict) -> Dict:
        """Calculate difference between two responses"""
        if not r1 or not r2:
            return {'error': 'Missing response'}

        diff = {
            'status_diff': r1.get('status') != r2.get('status'),
            'length_diff': abs(r1.get('content_length', 0) - r2.get('content_length', 0)),
            'length_ratio': 0,
            'content_diff': r1.get('content_hash') != r2.get('content_hash'),
            'header_diff': [],
            'text_diff': [],
        }

        # Length ratio
        max_len = max(r1.get('content_length', 1), r2.get('content_length', 1))
        diff['length_ratio'] = diff['length_diff'] / max_len if max_len > 0 else 0

        # Header differences
        h1 = set(r1.get('headers', {}).keys())
        h2 = set(r2.get('headers', {}).keys())
        diff['header_diff'] = list(h1.symmetric_difference(h2))

        # Text diff (if content is different)
        if diff['content_diff']:
            c1 = r1.get('content', '').split('\n')[:100]
            c2 = r2.get('content', '').split('\n')[:100]
            differ = difflib.unified_diff(c1, c2, lineterm='', n=0)
            diff['text_diff'] = list(differ)[:50]

        return diff

    # ==================== DIFFERENTIAL TESTS ====================

    def diff_header_variants(self, endpoints: List[str]):
        """Compare benign header variants (safe mode)"""
        self.log('info', '=== HEADER DIFFERENTIAL ===')

        variants = [
            {"Accept-Language": "en-US,en;q=0.9"},
            {"Accept-Language": "tr-TR,tr;q=0.9"},
            {"Accept": "application/json"},
            {"Cache-Control": "no-cache"},
            {"DNT": "1"},
        ]

        for endpoint in endpoints[:self.config.max_endpoints]:
            url = self.target + endpoint if endpoint.startswith('/') else endpoint
            resp_base, _ = self._request(url)
            norm_base = self._normalize_response(resp_base)

            for headers in variants:
                resp_var, _ = self._request(url, headers=headers)
                norm_var = self._normalize_response(resp_var)
                diff = self._calculate_diff(norm_base, norm_var)

                if diff.get('status_diff'):
                    self.add_finding(
                        f'Status change with header variant on {endpoint}',
                        'LOW',
                        {
                            'endpoint': endpoint,
                            'header': headers,
                            'base_status': norm_base.get('status'),
                            'variant_status': norm_var.get('status'),
                        }
                    )

                if diff.get('length_ratio', 0) > self.config.threshold:
                    self.add_finding(
                        f'Content change with header variant on {endpoint}',
                        'LOW',
                        {
                            'endpoint': endpoint,
                            'header': headers,
                            'length_diff': diff['length_diff'],
                            'length_ratio': f"{diff['length_ratio']*100:.1f}%",
                        }
                    )

    def diff_param_variants(self, endpoints: List[str]):
        """Compare benign parameter toggles (safe mode)"""
        self.log('info', '=== PARAMETER DIFFERENTIAL ===')

        param_sets = [
            {"page": "1"},
            {"limit": "1"},
            {"format": "json"},
            {"lang": "en"},
            {"view": "compact"},
            {"sort": "asc"},
            {"q": "test"},
        ]

        for endpoint in endpoints[:self.config.max_endpoints]:
            url = self.target + endpoint if endpoint.startswith('/') else endpoint

            resp_base, _ = self._request(url)
            norm_base = self._normalize_response(resp_base)
            if not norm_base:
                continue

            for params in param_sets:
                test_url = f"{url}?{urlencode(params)}"
                resp_test, _ = self._request(test_url)
                norm_test = self._normalize_response(resp_test)
                if not norm_test:
                    continue
                diff = self._calculate_diff(norm_base, norm_test)

                if diff.get('status_diff'):
                    self.add_finding(
                        f'Status change with param variant on {endpoint}',
                        'LOW',
                        {
                            'endpoint': endpoint,
                            'params': params,
                            'base_status': norm_base.get('status'),
                            'test_status': norm_test.get('status'),
                        }
                    )

                if diff.get('length_ratio', 0) > self.config.threshold:
                    self.add_finding(
                        f'Content change with param variant on {endpoint}',
                        'LOW',
                        {
                            'endpoint': endpoint,
                            'params': params,
                            'length_diff': diff['length_diff'],
                            'length_ratio': f"{diff['length_ratio']*100:.1f}%",
                        }
                    )

    def diff_param_presence(self, endpoints: List[str]):
        """Discover parameter sensitivity with benign values (safe mode)"""
        self.log('info', '=== PARAMETER PRESENCE ===')

        common_params = [
            'page', 'per_page', 'limit', 'offset', 'sort', 'order',
            'search', 'q', 'filter', 'format', 'lang', 'locale',
            'view', 'mode', 'type', 'category', 'tag',
        ]

        for endpoint in endpoints[:self.config.max_endpoints]:
            url = self.target + endpoint if endpoint.startswith('/') else endpoint
            resp_base, _ = self._request(url)
            norm_base = self._normalize_response(resp_base)
            if not norm_base:
                continue

            for param in common_params:
                test_values = ['1', '10', 'asc', 'desc', 'en']
                for value in test_values:
                    test_url = f"{url}?{param}={value}"
                    resp_test, _ = self._request(test_url)
                    norm_test = self._normalize_response(resp_test)
                    if not norm_test:
                        continue
                    diff = self._calculate_diff(norm_base, norm_test)
                    if diff.get('length_ratio', 0) > self.config.threshold:
                        self.add_finding(
                            f'Param sensitivity: {param}={value}',
                            'LOW',
                            {
                                'endpoint': endpoint,
                                'parameter': param,
                                'value': value,
                                'length_diff': diff['length_diff'],
                                'length_ratio': f"{diff['length_ratio']*100:.1f}%",
                            }
                        )
                        break
                    if diff.get('status_diff'):
                        self.add_finding(
                            f'Status change with param: {param}={value}',
                            'LOW',
                            {
                                'endpoint': endpoint,
                                'parameter': param,
                                'value': value,
                                'base_status': norm_base.get('status'),
                                'test_status': norm_test.get('status'),
                            }
                        )
                        break

    def diff_graphql_fields(self, graphql_endpoint: str = '/graphql'):
        """Check GraphQL baseline responses (safe mode)"""
        self.log('info', '=== GRAPHQL DIFFERENTIAL ===')

        url = self.target + graphql_endpoint
        baseline_query = '{ __typename }'
        resp_base, _ = self._request(url, method='POST', json={'query': baseline_query})
        norm_base = self._normalize_response(resp_base)

        if self.config.allow_graphql_introspection:
            introspection = '{ __schema { types { name } } }'
            resp_intro, _ = self._request(url, method='POST', json={'query': introspection})
            norm_intro = self._normalize_response(resp_intro)
            diff = self._calculate_diff(norm_base, norm_intro)
            if diff.get('content_diff'):
                self.add_finding(
                    'GraphQL introspection available',
                    'LOW',
                    {
                        'endpoint': graphql_endpoint,
                        'status': norm_intro.get('status'),
                        'length_diff': diff.get('length_diff'),
                    }
                )

    def diff_timing(self, endpoints: List[str]):
        """Response timing variance analysis (safe mode)"""
        self.log('info', '=== TIMING DIFFERENTIAL ===')

        for endpoint in endpoints[:20]:
            url = self.target + endpoint if endpoint.startswith('/') else endpoint

            times_base = []
            for _ in range(3):
                _, t = self._request(url)
                times_base.append(t)
                time.sleep(0.1)

            avg_base = sum(times_base) / len(times_base) if times_base else 0

            cachebust = int(time.time() * 1000)
            test_url = f"{url}?cb={cachebust}"
            _, t = self._request(test_url)

            if avg_base > 0 and t > avg_base * 2.5:
                self.add_finding(
                    f'Timing variance on {endpoint}',
                    'LOW',
                    {
                        'endpoint': endpoint,
                        'base_time': f'{avg_base:.2f}s',
                        'test_time': f'{t:.2f}s',
                        'multiplier': f'{t / avg_base:.2f}x',
                    }
                )

    def diff_error_messages(self, endpoints: List[str]):
        """Analyze error message variations"""
        self.log('info', '=== ERROR MESSAGE DIFFERENTIAL ===')

        error_triggers = [
            ('invalid_id', '?id=999999999'),
            ('string_id', '?id=test'),
            ('negative_id', '?id=-1'),
            ('null', '?id=null'),
            ('undefined', '?id=undefined'),
            ('empty', '?id='),
            ('array', '?id[]=1'),
            ('object', '?id[key]=value'),
            ('special', '?id=<>'),
            ('unicode', '?id=%00%ff'),
        ]

        for endpoint in endpoints[:30]:
            url = self.target + endpoint if endpoint.startswith('/') else endpoint

            # Baseline
            resp_base, _ = self._request(url)

            for name, trigger in error_triggers:
                test_url = url + trigger
                resp, _ = self._request(test_url)

                if resp and resp.status_code >= 400:
                    # Check for information disclosure in error
                    error_patterns = [
                        (r'stack\s*:\s*', 'Stack trace'),
                        (r'at\s+\w+\s+\([^)]+:\d+:\d+\)', 'Stack trace'),
                        (r'/[a-zA-Z0-9_/.-]+\.(?:js|ts|py|rb|php)', 'File path'),
                        (r'line\s+\d+', 'Line number'),
                        (r'column\s+\d+', 'Column number'),
                        (r'(?:mysql|postgres|mongodb|redis)', 'Database type'),
                        (r'(?:SQLSTATE|ORA-|PG::)', 'Database error'),
                        (r'(?:root|admin|www-data):', 'System user'),
                        (r'(?:password|secret|key)\s*[:=]', 'Credential hint'),
                    ]

                    for pattern, desc in error_patterns:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            self.add_finding(
                                f'{desc} in error response on {endpoint}',
                                'MEDIUM',
                                {
                                    'endpoint': endpoint,
                                    'trigger': name,
                                    'pattern': pattern,
                                    'status': resp.status_code,
                                }
                            )
                            break


    # ==================== MAIN ====================

    def run(self, endpoints: List[str] = None, graphql: str = None):
        """Run differential analysis"""
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}Differential Hunter v2.0{Colors.END}")
        print(f"{'='*70}")
        print(f"Target: {self.target}")
        print(f"{'='*70}\n")

        # Get endpoints if not provided
        if not endpoints:
            endpoints = self._discover_endpoints()

        self.log('success', f'Analyzing {len(endpoints)} endpoints')

        if not self.security_findings:
            resp, _ = self._request(self.target)
            if resp:
                self.security_findings = evaluate_security_headers(
                    resp.headers,
                    resp.headers.get("content-type", ""),
                )

        # Run all differential tests
        self.diff_header_variants(endpoints)
        self.diff_param_variants(endpoints)
        self.diff_param_presence(endpoints)
        self.diff_timing(endpoints[:10])  # Limit timing tests
        self.diff_error_messages(endpoints)

        # GraphQL if available
        if graphql:
            self.diff_graphql_fields(graphql)
        else:
            # Try common endpoints
            for ep in ['/graphql', '/api/graphql', '/gql']:
                try:
                    resp, _ = self._request(self.target + ep, method='POST',
                                           json={'query': '{ __typename }'})
                    if resp and resp.status_code == 200:
                        self.diff_graphql_fields(ep)
                        break
                except:
                    pass

        return self.generate_report()

    def _discover_endpoints(self) -> List[str]:
        """Basic endpoint discovery"""
        endpoints = ['/']

        # Fetch homepage for links
        resp, _ = self._request(self.target)
        if resp:
            if not self.security_findings:
                self.security_findings = evaluate_security_headers(
                    resp.headers,
                    resp.headers.get("content-type", ""),
                )
            for match in re.findall(r'href=["\']([^"\']+)["\']', resp.text):
                if match.startswith('/') and not any(match.endswith(ext) for ext in ['.css', '.js', '.png', '.jpg', '.svg', '.ico']):
                    path = match.split('?')[0]
                    if path not in endpoints:
                        endpoints.append(path)

        # Common paths
        common = ['/api', '/api/health', '/api/user', '/api/users', '/api/config',
                  '/api/v1', '/api/v1/user', '/admin', '/login', '/auth', '/graphql']
        for path in common:
            if path not in endpoints:
                endpoints.append(path)

        return endpoints[:self.config.max_endpoints]

    def generate_report(self):
        """Generate differential analysis report"""
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}DIFFERENTIAL ANALYSIS COMPLETE{Colors.END}")
        print(f"{'='*70}")

        print(f"\n{Colors.CYAN}Findings Summary:{Colors.END}")

        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in self.findings:
            sev = f.get('severity', 'LOW')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        for sev, count in severity_counts.items():
            if count > 0:
                color = {'CRITICAL': Colors.RED, 'HIGH': Colors.RED, 'MEDIUM': Colors.YELLOW, 'LOW': Colors.BLUE}.get(sev, '')
                print(f"  {color}{sev}: {count}{Colors.END}")

        if self.security_findings:
            summary = summarize_findings(self.security_findings)
            print(f"\n{Colors.CYAN}Security Headers Summary:{Colors.END}")
            print(f"  {summary}")

        # Print top findings
        if self.findings:
            print(f"\n{Colors.CYAN}Key Findings:{Colors.END}")
            for f in sorted(self.findings, key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(x['severity'], 4))[:10]:
                sev = f.get('severity')
                color = {'CRITICAL': Colors.RED, 'HIGH': Colors.RED, 'MEDIUM': Colors.YELLOW}.get(sev, '')
                print(f"  {color}[{sev}] {f.get('title')}{Colors.END}")

        # Save report
        report = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'request_count': self.request_count,
            'security_findings': self.security_findings,
            'security_summary': summarize_findings(self.security_findings),
            'summary': severity_counts,
            'findings': self.findings,
        }

        report_path = os.path.join(self.output_path, 'differential_report.json')
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n{Colors.GREEN}Report saved: {report_path}{Colors.END}")

        return report


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Differential Hunter')
    parser.add_argument('target', help='Target URL')
    parser.add_argument('-e', '--endpoints', help='File with endpoints')
    parser.add_argument('-g', '--graphql', help='GraphQL endpoint')
    parser.add_argument('-o', '--output', default='diff_analysis', help='Output directory')
    parser.add_argument('-t', '--threads', type=int, default=8, help='Concurrent threads')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout')
    parser.add_argument('--delay', type=float, default=0.2, help='Delay between requests')
    parser.add_argument('--threshold', type=float, default=0.1, help='Diff threshold ratio')
    parser.add_argument('--max-endpoints', type=int, default=50, help='Max endpoints')
    parser.add_argument('--max-bytes', type=int, default=2000000, help='Max response size')
    parser.add_argument('--max-lines', type=int, default=100, help='Max diff lines')
    parser.add_argument('--retries', type=int, default=2, help='Retry count')
    parser.add_argument('--backoff', type=float, default=0.3, help='Retry backoff factor')
    parser.add_argument('--verify-ssl', action='store_true', help='Verify TLS certificates')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--allow-introspection', action='store_true', help='Allow GraphQL introspection check')
    parser.add_argument('--allow-host', action='append', default=[], help='Allowed hostnames')
    parser.add_argument('--allow-suffix', action='append', default=[], help='Allowed host suffixes')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    config = DiffConfig(
        output_dir=args.output,
        concurrency=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        threshold=args.threshold,
        max_endpoints=args.max_endpoints,
        max_response_bytes=args.max_bytes,
        max_text_lines=args.max_lines,
        retries=args.retries,
        backoff_factor=args.backoff,
        verify_ssl=args.verify_ssl,
        no_color=args.no_color,
        allow_graphql_introspection=args.allow_introspection,
        allowed_hosts=args.allow_host,
        allowed_suffixes=args.allow_suffix,
        verbose=args.verbose,
    )

    hunter = DifferentialHunter(args.target, config)

    endpoints = None
    if args.endpoints and os.path.exists(args.endpoints):
        with open(args.endpoints) as f:
            endpoints = [l.strip() for l in f if l.strip()]

    hunter.run(endpoints=endpoints, graphql=args.graphql)


if __name__ == '__main__':
    main()
