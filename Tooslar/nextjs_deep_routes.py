#!/usr/bin/env python3
"""
Next.js Deep Route Discovery v1.0
Extracts ALL routes from Next.js applications using multiple techniques

Techniques:
1. _buildManifest.js parsing - Contains all page routes
2. _ssgManifest.js parsing - Contains static generation routes
3. _next/data/[buildId]/ enumeration - Data routes
4. Webpack chunk analysis - Dynamic imports reveal routes
5. Router component analysis - Link hrefs and router.push calls
6. API route discovery - /api/* patterns
7. Middleware detection - Route rewrites and redirects
8. i18n route detection - Locale-prefixed routes

Author: Security Research Team
"""

import requests
import re
import json
import sys
import os
from urllib.parse import urljoin, urlparse, quote
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
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
    DIM = "\033[2m"
    END = "\033[0m"


class NextJSDeepRoutes:
    """
    Deep route discovery for Next.js applications
    """

    def __init__(self, target: str, output_dir: str = ".", verbose: bool = False):
        self.target = target.rstrip('/')
        self.output_dir = output_dir
        self.verbose = verbose

        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
        self.session.verify = False

        # Discovered data
        self.build_id: Optional[str] = None
        self.routes: Dict[str, Dict] = {}  # path -> metadata
        self.api_routes: Set[str] = set()
        self.data_routes: Set[str] = set()
        self.static_routes: Set[str] = set()
        self.dynamic_routes: Set[str] = set()
        self.protected_routes: Set[str] = set()
        self.locales: Set[str] = set()
        self.chunks: Dict[str, str] = {}  # chunk name -> content
        self.manifests: Dict[str, Dict] = {}

        # Route patterns found
        self.route_patterns: List[Dict] = []

    def log(self, level: str, msg: str):
        colors = {
            'info': Colors.BLUE,
            'success': Colors.GREEN,
            'warning': Colors.YELLOW,
            'error': Colors.RED,
            'route': Colors.PURPLE,
            'api': Colors.CYAN,
        }
        color = colors.get(level, '')
        print(f"{color}[{level.upper()}]{Colors.END} {msg}")

    def run(self) -> Dict:
        """Run full route discovery"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.PURPLE}   NEXT.JS DEEP ROUTE DISCOVERY v1.0{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"Target: {self.target}")
        print()

        # Step 1: Get initial page and build ID
        self._get_build_id()

        # Step 2: Parse build manifest
        self._parse_build_manifest()

        # Step 3: Parse SSG manifest
        self._parse_ssg_manifest()

        # Step 4: Discover API routes
        self._discover_api_routes()

        # Step 5: Analyze webpack chunks for routes
        self._analyze_chunks_for_routes()

        # Step 6: Discover data routes
        self._discover_data_routes()

        # Step 7: Detect middleware routes
        self._detect_middleware_routes()

        # Step 8: Enumerate locales
        self._enumerate_locales()

        # Step 9: Find protected routes
        self._find_protected_routes()

        # Step 10: Verify routes
        self._verify_routes()

        # Generate report
        return self._generate_report()

    def _get_build_id(self):
        """Extract build ID from the page"""
        self.log('info', 'Extracting build ID...')

        try:
            resp = self.session.get(self.target, timeout=30)
            html = resp.text

            # Method 1: From _next/data path
            match = re.search(r'/_next/data/([a-zA-Z0-9_-]+)/', html)
            if match:
                self.build_id = match.group(1)

            # Method 2: From buildId in script
            if not self.build_id:
                match = re.search(r'"buildId"\s*:\s*"([^"]+)"', html)
                if match:
                    self.build_id = match.group(1)

            # Method 3: From _buildManifest
            if not self.build_id:
                match = re.search(r'/_next/static/([a-zA-Z0-9_-]+)/_buildManifest\.js', html)
                if match:
                    self.build_id = match.group(1)

            # Method 4: From chunk files
            if not self.build_id:
                match = re.search(r'/_next/static/chunks/pages/_app-([a-f0-9]+)\.js', html)
                if match:
                    # This is not buildId but hash, look elsewhere
                    pass

            if self.build_id:
                self.log('success', f'Build ID: {self.build_id}')
            else:
                self.log('warning', 'Could not find build ID')

            # Store HTML for later analysis
            self.html = html

        except Exception as e:
            self.log('error', f'Error getting page: {e}')
            self.html = ""

    def _parse_build_manifest(self):
        """Parse _buildManifest.js for routes"""
        self.log('info', 'Parsing build manifest...')

        if not self.build_id:
            return

        manifest_url = f"{self.target}/_next/static/{self.build_id}/_buildManifest.js"

        try:
            resp = self.session.get(manifest_url, timeout=20)
            if resp.status_code != 200:
                # Try without build ID
                manifest_url = f"{self.target}/_next/static/chunks/_buildManifest.js"
                resp = self.session.get(manifest_url, timeout=20)

            if resp.status_code == 200:
                content = resp.text
                self.manifests['build'] = {'url': manifest_url, 'content': content}

                # Parse routes from manifest
                # Format: self.__BUILD_MANIFEST = {...}
                # or: __BUILD_MANIFEST={...}

                # Extract JSON-like object
                # Handle both direct object and IIFE format
                # Direct: self.__BUILD_MANIFEST = {...}
                # IIFE: self.__BUILD_MANIFEST = (function(a,b){return {...}})(...)
                match = re.search(r'__BUILD_MANIFEST\s*=\s*(?:\(function[^{]*\{return\s*)?(\{[^;]+)', content, re.DOTALL)
                if match:
                    manifest_str = match.group(1)

                    # Find all route keys
                    # Routes look like: "/": [...], "/about": [...], "/blog/[slug]": [...]
                    # Also handle IIFE format with variable references: "/":[a,b]
                    route_pattern = r'"(/[^"]*)":\s*\['
                    routes = re.findall(route_pattern, manifest_str)

                    # Fallback: try to find any quoted path that looks like a route
                    if not routes:
                        route_pattern = r'"(/(?:[^"]*)?)":\['
                        routes = re.findall(route_pattern, manifest_str)

                    for route in routes:
                        if route not in ['/__next_error__']:
                            self.routes[route] = {
                                'source': 'buildManifest',
                                'type': 'dynamic' if '[' in route else 'static',
                                'verified': False
                            }

                            if '[' in route:
                                self.dynamic_routes.add(route)
                            else:
                                self.static_routes.add(route)

                self.log('success', f'Found {len(self.routes)} routes in build manifest')

        except Exception as e:
            self.log('warning', f'Could not parse build manifest: {e}')

    def _parse_ssg_manifest(self):
        """Parse _ssgManifest.js for static generation routes"""
        self.log('info', 'Parsing SSG manifest...')

        if not self.build_id:
            return

        manifest_url = f"{self.target}/_next/static/{self.build_id}/_ssgManifest.js"

        try:
            resp = self.session.get(manifest_url, timeout=20)

            if resp.status_code == 200:
                content = resp.text
                self.manifests['ssg'] = {'url': manifest_url, 'content': content}

                # Format: self.__SSG_MANIFEST=new Set(["path1","path2",...])
                match = re.search(r'__SSG_MANIFEST\s*=\s*new\s+Set\s*\(\s*\[(.*?)\]\s*\)', content, re.DOTALL)
                if match:
                    paths_str = match.group(1)
                    paths = re.findall(r'"([^"]+)"', paths_str)

                    for path in paths:
                        if path not in self.routes:
                            self.routes[path] = {
                                'source': 'ssgManifest',
                                'type': 'ssg',
                                'verified': False
                            }
                        else:
                            self.routes[path]['ssg'] = True

                    self.log('success', f'Found {len(paths)} SSG routes')

        except Exception as e:
            if self.verbose:
                self.log('warning', f'Could not parse SSG manifest: {e}')

    def _discover_api_routes(self):
        """Discover API routes from various sources"""
        self.log('info', 'Discovering API routes...')

        # Known API patterns from chunks
        api_patterns = set()

        # Pattern 1: From HTML/JS - "/api/..." strings
        all_content = self.html
        for chunk_content in self.chunks.values():
            all_content += chunk_content

        # Find /api/... patterns
        for match in re.finditer(r'["\'](/api/[a-zA-Z0-9/_\-\[\]]+)["\']', all_content):
            api_patterns.add(match.group(1))

        # Find fetch/axios to /api
        for match in re.finditer(r'(?:fetch|axios|get|post|put|delete)\s*\(\s*[`"\'](/api/[^`"\']+)', all_content):
            path = match.group(1).split('?')[0]
            api_patterns.add(path)

        # Common API routes to check
        common_apis = [
            '/api/auth',
            '/api/auth/session',
            '/api/auth/signin',
            '/api/auth/signout',
            '/api/auth/callback',
            '/api/auth/csrf',
            '/api/auth/providers',
            '/api/user',
            '/api/users',
            '/api/me',
            '/api/profile',
            '/api/search',
            '/api/graphql',
            '/api/health',
            '/api/status',
            '/api/config',
            '/api/settings',
            '/api/webhook',
            '/api/webhooks',
            '/api/preview',
            '/api/revalidate',
            '/api/og',  # OpenGraph image generation
            '/api/sitemap',
            '/api/robots',
            '/api/feed',
            '/api/rss',
            '/api/trpc',  # tRPC endpoint
        ]

        for api in common_apis:
            api_patterns.add(api)

        # Verify API routes exist
        self.log('info', f'Checking {len(api_patterns)} potential API routes...')

        def check_api(path):
            try:
                url = f"{self.target}{path}"
                resp = self.session.get(url, timeout=10, allow_redirects=False)

                if resp.status_code not in [404, 500, 502, 503]:
                    return (path, {
                        'status': resp.status_code,
                        'content_type': resp.headers.get('Content-Type', ''),
                        'size': len(resp.content)
                    })
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_api, path): path for path in api_patterns}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    path, info = result
                    self.api_routes.add(path)
                    self.routes[path] = {
                        'source': 'api_discovery',
                        'type': 'api',
                        'verified': True,
                        **info
                    }

        self.log('success', f'Found {len(self.api_routes)} verified API routes')

    def _analyze_chunks_for_routes(self):
        """Analyze webpack chunks for route information"""
        self.log('info', 'Analyzing webpack chunks...')

        # Download main chunks if not already
        if not self.chunks:
            # Find chunk URLs from HTML
            chunk_patterns = [
                r'"(/\_next/static/chunks/[^"]+\.js)"',
                r"'(/\_next/static/chunks/[^']+\.js)'",
                r'"(/\_next/static/[^/]+/pages/[^"]+\.js)"',
            ]

            chunk_urls = set()
            for pattern in chunk_patterns:
                for match in re.findall(pattern, self.html):
                    chunk_urls.add(match)

            # Download chunks (limit to important ones)
            important_chunks = [url for url in chunk_urls if any(x in url for x in ['pages/', 'main', 'app-', 'webpack'])]

            for chunk_path in important_chunks[:20]:
                try:
                    url = urljoin(self.target, chunk_path)
                    resp = self.session.get(url, timeout=20)
                    if resp.status_code == 200:
                        self.chunks[chunk_path] = resp.text
                except:
                    pass

        # Analyze chunks for routes
        all_chunk_content = '\n'.join(self.chunks.values())

        # Pattern 1: Pages directory structure
        for match in re.finditer(r'pages[/\\]([a-zA-Z0-9/_\[\]\-]+)(?:\.tsx|\.ts|\.jsx|\.js)', all_chunk_content):
            route = '/' + match.group(1).replace('index', '').rstrip('/')
            route = route if route else '/'
            if route not in self.routes:
                self.routes[route] = {'source': 'chunk_analysis', 'type': 'page'}

        # Pattern 2: App directory structure (App Router)
        for match in re.finditer(r'app[/\\]([a-zA-Z0-9/_\[\]\-]+)[/\\]page', all_chunk_content):
            route = '/' + match.group(1)
            if route not in self.routes:
                self.routes[route] = {'source': 'chunk_analysis', 'type': 'app_router'}

        # Pattern 3: router.push / Link href
        for match in re.finditer(r'(?:router\.push|Router\.push|href)\s*[(:=]\s*[`"\']([^`"\']+)[`"\']', all_chunk_content):
            route = match.group(1)
            if route.startswith('/') and '[' not in route and not route.startswith('/_'):
                if route not in self.routes:
                    self.routes[route] = {'source': 'chunk_analysis', 'type': 'navigation'}

        # Pattern 4: getServerSideProps / getStaticProps paths
        for match in re.finditer(r'getS(?:tatic|erverSide)Props.*?pathname["\']?\s*:\s*["\']([^"\']+)', all_chunk_content):
            route = match.group(1)
            if route not in self.routes:
                self.routes[route] = {'source': 'chunk_analysis', 'type': 'ssr'}

        # Pattern 5: Dynamic import paths
        for match in re.finditer(r'import\s*\(\s*[`"\'](?:\.\.?/)?pages?[/\\]([^`"\']+)[`"\']', all_chunk_content):
            route = '/' + match.group(1).replace('.tsx', '').replace('.ts', '').replace('.js', '').replace('/index', '')
            if route not in self.routes:
                self.routes[route] = {'source': 'chunk_analysis', 'type': 'dynamic_import'}

        self.log('success', f'Found {len(self.routes)} total routes after chunk analysis')

    def _discover_data_routes(self):
        """Discover _next/data routes"""
        self.log('info', 'Discovering data routes...')

        if not self.build_id:
            return

        # Data routes correspond to pages with getServerSideProps or getStaticProps
        for route in list(self.routes.keys()):
            if route.startswith('/api/') or route.startswith('/_'):
                continue

            # Convert route to data URL
            data_path = route.rstrip('/')
            if not data_path:
                data_path = '/index'

            data_url = f"{self.target}/_next/data/{self.build_id}{data_path}.json"

            try:
                resp = self.session.get(data_url, timeout=10)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        self.data_routes.add(route)
                        self.routes[route]['has_data'] = True
                        self.routes[route]['data_url'] = data_url

                        # Check for interesting data
                        data_str = json.dumps(data)
                        if 'user' in data_str.lower() or 'auth' in data_str.lower():
                            self.routes[route]['interesting'] = 'contains_user_data'
                        if 'token' in data_str.lower() or 'key' in data_str.lower():
                            self.routes[route]['interesting'] = 'contains_tokens'

                    except:
                        pass
            except:
                pass

        self.log('success', f'Found {len(self.data_routes)} routes with data')

    def _detect_middleware_routes(self):
        """Detect middleware-affected routes"""
        self.log('info', 'Detecting middleware routes...')

        # Look for middleware patterns in chunks
        all_content = '\n'.join(self.chunks.values()) + self.html

        # Middleware config patterns
        middleware_patterns = [
            r'matcher\s*:\s*\[([^\]]+)\]',
            r'config\s*=\s*\{[^}]*matcher\s*:\s*([^\}]+)',
            r'middleware\s*\(\s*request.*?(?:pathname|path)\s*===?\s*["\']([^"\']+)',
        ]

        middleware_routes = set()
        for pattern in middleware_patterns:
            for match in re.finditer(pattern, all_content, re.DOTALL):
                paths = re.findall(r'["\']([^"\']+)["\']', match.group(1) if match.lastindex else match.group(0))
                for path in paths:
                    if path.startswith('/'):
                        middleware_routes.add(path)

        for route in middleware_routes:
            if route not in self.routes:
                self.routes[route] = {'source': 'middleware', 'type': 'middleware'}
            else:
                self.routes[route]['has_middleware'] = True

        if middleware_routes:
            self.log('success', f'Found {len(middleware_routes)} middleware routes')

    def _enumerate_locales(self):
        """Enumerate i18n locales"""
        self.log('info', 'Enumerating locales...')

        all_content = '\n'.join(self.chunks.values()) + self.html

        # Common locales and detection patterns
        locale_patterns = [
            r'locales\s*:\s*\[([^\]]+)\]',
            r'i18n\s*:\s*\{[^}]*locales\s*:\s*\[([^\]]+)',
            r'defaultLocale\s*:\s*["\']([^"\']+)',
        ]

        for pattern in locale_patterns:
            for match in re.finditer(pattern, all_content):
                locales = re.findall(r'["\']([a-z]{2}(?:-[A-Z]{2})?)["\']', match.group(1) if match.lastindex else match.group(0))
                self.locales.update(locales)

        # Also check URL patterns
        for match in re.finditer(r'href=["\']/((?:en|de|fr|es|it|ja|ko|zh|pt|ru|ar|nl|pl|tr|vi|th|id)(?:-[A-Z]{2})?)/[^"\']+', all_content):
            self.locales.add(match.group(1))

        if self.locales:
            self.log('success', f'Found locales: {", ".join(self.locales)}')

            # Add locale-prefixed routes
            for route in list(self.routes.keys()):
                if not route.startswith('/_') and not route.startswith('/api/'):
                    for locale in self.locales:
                        locale_route = f"/{locale}{route}" if route != '/' else f"/{locale}"
                        if locale_route not in self.routes:
                            self.routes[locale_route] = {
                                'source': 'i18n',
                                'type': 'locale',
                                'base_route': route
                            }

    def _find_protected_routes(self):
        """Find routes that appear to be protected"""
        self.log('info', 'Finding protected routes...')

        all_content = '\n'.join(self.chunks.values()) + self.html

        # Protected route patterns
        protected_keywords = [
            'protected', 'private', 'authenticated', 'requireAuth', 'withAuth',
            'useSession', 'getSession', 'isAuthenticated', 'checkAuth',
            'authRequired', 'loginRequired', 'privateRoute', 'guardedRoute'
        ]

        for route in self.routes.keys():
            route_pattern = re.escape(route).replace(r'\[', r'\\[').replace(r'\]', r'\\]')

            # Check if route appears near protection keywords
            for keyword in protected_keywords:
                pattern = rf'{keyword}[^}}]{{0,200}}{route_pattern}|{route_pattern}[^}}]{{0,200}}{keyword}'
                if re.search(pattern, all_content, re.IGNORECASE):
                    self.protected_routes.add(route)
                    self.routes[route]['protected'] = True
                    break

        # Routes with common protected names
        protected_names = ['admin', 'dashboard', 'settings', 'profile', 'account', 'billing', 'internal']
        for route in self.routes.keys():
            if any(name in route.lower() for name in protected_names):
                self.protected_routes.add(route)
                self.routes[route]['likely_protected'] = True

        self.log('success', f'Found {len(self.protected_routes)} likely protected routes')

    def _verify_routes(self):
        """Verify discovered routes exist"""
        self.log('info', 'Verifying routes...')

        static_routes = [r for r, info in self.routes.items()
                         if '[' not in r and not info.get('verified')
                         and not r.startswith('/api/')]

        def check_route(route):
            try:
                url = f"{self.target}{route}"
                resp = self.session.get(url, timeout=10, allow_redirects=False)
                return (route, resp.status_code)
            except:
                return (route, None)

        verified = 0
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_route, route): route for route in static_routes[:50]}
            for future in as_completed(futures):
                route, status = future.result()
                if status and status not in [404, 500]:
                    self.routes[route]['verified'] = True
                    self.routes[route]['status'] = status
                    verified += 1

        self.log('success', f'Verified {verified} routes')

    def _generate_report(self) -> Dict:
        """Generate and save report"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.PURPLE}   ROUTE DISCOVERY RESULTS{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")

        # Summary
        print(f"\n{Colors.CYAN}Summary:{Colors.END}")
        print(f"  Build ID: {self.build_id or 'Not found'}")
        print(f"  Total Routes: {len(self.routes)}")
        print(f"  API Routes: {len(self.api_routes)}")
        print(f"  Data Routes: {len(self.data_routes)}")
        print(f"  Static Routes: {len(self.static_routes)}")
        print(f"  Dynamic Routes: {len(self.dynamic_routes)}")
        print(f"  Protected Routes: {len(self.protected_routes)}")
        print(f"  Locales: {', '.join(self.locales) or 'None'}")

        # API Routes
        if self.api_routes:
            print(f"\n{Colors.YELLOW}API Routes:{Colors.END}")
            for route in sorted(self.api_routes):
                info = self.routes.get(route, {})
                status = info.get('status', '?')
                print(f"  [{status}] {route}")

        # Protected Routes
        if self.protected_routes:
            print(f"\n{Colors.RED}Protected Routes:{Colors.END}")
            for route in sorted(self.protected_routes):
                print(f"  {route}")

        # Dynamic Routes
        if self.dynamic_routes:
            print(f"\n{Colors.BLUE}Dynamic Routes (need parameters):{Colors.END}")
            for route in sorted(self.dynamic_routes)[:20]:
                print(f"  {route}")

        # Interesting routes
        interesting = [(r, info) for r, info in self.routes.items() if info.get('interesting')]
        if interesting:
            print(f"\n{Colors.GREEN}Interesting Routes:{Colors.END}")
            for route, info in interesting:
                print(f"  {route} - {info.get('interesting')}")

        # Save report
        report = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'build_id': self.build_id,
            'summary': {
                'total_routes': len(self.routes),
                'api_routes': len(self.api_routes),
                'data_routes': len(self.data_routes),
                'static_routes': len(self.static_routes),
                'dynamic_routes': len(self.dynamic_routes),
                'protected_routes': len(self.protected_routes),
            },
            'locales': list(self.locales),
            'routes': self.routes,
            'api_routes': list(self.api_routes),
            'protected_routes': list(self.protected_routes),
            'dynamic_routes': list(self.dynamic_routes),
        }

        # Save
        report_dir = os.path.join(self.output_dir, 'route_discovery')
        os.makedirs(report_dir, exist_ok=True)

        report_file = os.path.join(report_dir, 'routes_report.json')
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        # Save routes as text
        routes_file = os.path.join(report_dir, 'all_routes.txt')
        with open(routes_file, 'w') as f:
            for route in sorted(self.routes.keys()):
                f.write(route + '\n')

        # Save API routes
        api_file = os.path.join(report_dir, 'api_routes.txt')
        with open(api_file, 'w') as f:
            for route in sorted(self.api_routes):
                f.write(route + '\n')

        print(f"\n{Colors.GREEN}Reports saved to: {report_dir}{Colors.END}")

        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: python nextjs_deep_routes.py <target_url> [-v]")
        print("Example: python nextjs_deep_routes.py https://example.com -v")
        sys.exit(1)

    target = sys.argv[1]
    verbose = '-v' in sys.argv or '--verbose' in sys.argv

    scanner = NextJSDeepRoutes(target, verbose=verbose)
    scanner.run()


if __name__ == "__main__":
    main()
