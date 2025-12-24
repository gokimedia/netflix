#!/usr/bin/env python3
"""
Deep Extractor v1.0 - Beyond Regex Extraction
Goes DEEP into JavaScript bundles to find hidden endpoints, APIs, and secrets

What makes this DEEP:
1. Webpack Bundle Parser - Parses actual webpack module structure
2. Variable Tracker - Tracks variable assignments across code
3. Object Deep Extractor - Extracts nested config objects
4. String Concatenation Resolver - Resolves dynamic URL building
5. Data Flow Analyzer - Follows how URLs are constructed
6. Module Export Analyzer - Finds exported API configurations
7. Function Call Tracer - Traces all function calls with URL params
8. AST-like Pattern Matching - Smarter than regex

Author: Security Research Team
"""

import requests
import re
import json
import sys
import os
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Set, Tuple, Any, Optional
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
    DIM = "\033[2m"
    END = "\033[0m"


@dataclass
class DeepFinding:
    """A finding from deep extraction"""
    type: str
    value: str
    source_file: str
    context: str
    confidence: str  # high, medium, low
    extraction_method: str
    metadata: Dict = field(default_factory=dict)


class WebpackBundleParser:
    """
    Parses Webpack bundle structure to extract modules
    Goes beyond regex by understanding bundle format
    """

    def __init__(self, content: str, url: str):
        self.content = content
        self.url = url
        self.modules: Dict[str, str] = {}
        self.chunks: Dict[str, List[str]] = {}
        self.exports: Dict[str, Any] = {}

    def parse(self) -> Dict:
        """Parse webpack bundle and extract modules"""
        result = {
            'modules': [],
            'chunks': [],
            'exports': [],
            'require_calls': [],
            'dynamic_imports': [],
        }

        # Pattern 1: Webpack 4/5 format - (self.webpackChunk = self.webpackChunk || []).push
        webpack5_pattern = r'(?:self|window|globalThis)\["webpackChunk[^"]*"\]\s*=\s*(?:self|window|globalThis)\["webpackChunk[^"]*"\]\s*\|\|\s*\[\]'
        if re.search(webpack5_pattern, self.content):
            result['format'] = 'webpack5'
            self._parse_webpack5(result)

        # Pattern 2: Webpack 4 JSONP - webpackJsonp
        elif 'webpackJsonp' in self.content:
            result['format'] = 'webpack4_jsonp'
            self._parse_webpack4_jsonp(result)

        # Pattern 3: Old webpack format - __webpack_require__
        elif '__webpack_require__' in self.content:
            result['format'] = 'webpack_legacy'
            self._parse_webpack_legacy(result)

        # Pattern 4: ES modules bundled
        elif 'import(' in self.content or 'export ' in self.content:
            result['format'] = 'esm_bundle'
            self._parse_esm_bundle(result)

        # Extract require calls regardless of format
        self._extract_require_calls(result)

        # Extract dynamic imports
        self._extract_dynamic_imports(result)

        return result

    def _parse_webpack5(self, result: Dict):
        """Parse Webpack 5 bundle format"""
        # Find push calls with module arrays
        # Format: .push([[chunkId], {moduleId: function(module, exports, require){...}}])
        push_pattern = r'\.push\(\[\[([^\]]+)\],\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}'

        for match in re.finditer(push_pattern, self.content, re.DOTALL):
            chunk_ids = match.group(1)
            modules_str = match.group(2)

            result['chunks'].append({
                'ids': chunk_ids.split(','),
                'raw_length': len(modules_str)
            })

            # Extract module IDs
            module_ids = re.findall(r'(\d+|"[^"]+"|\'[^\']+\'):\s*(?:function|\()', modules_str)
            for mod_id in module_ids:
                result['modules'].append({
                    'id': mod_id.strip('"\''),
                    'chunk': chunk_ids
                })

    def _parse_webpack4_jsonp(self, result: Dict):
        """Parse Webpack 4 JSONP format"""
        # Format: (window.webpackJsonp = window.webpackJsonp || []).push([[chunkId], {...}])
        jsonp_pattern = r'webpackJsonp[^.]*\.push\(\[\[([^\]]+)\],\s*(\{[^}]+\}|\[[^\]]+\])'

        for match in re.finditer(jsonp_pattern, self.content):
            chunk_id = match.group(1)
            result['chunks'].append({
                'id': chunk_id,
                'type': 'jsonp'
            })

    def _parse_webpack_legacy(self, result: Dict):
        """Parse legacy webpack format"""
        # Find __webpack_require__(moduleId)
        require_pattern = r'__webpack_require__\((\d+|"[^"]+"|\'[^\']+\')\)'

        seen = set()
        for match in re.finditer(require_pattern, self.content):
            mod_id = match.group(1).strip('"\'')
            if mod_id not in seen:
                seen.add(mod_id)
                result['modules'].append({'id': mod_id})

    def _parse_esm_bundle(self, result: Dict):
        """Parse ES modules bundle"""
        # Find dynamic imports
        import_pattern = r'import\s*\(\s*[`"\']([^`"\']+)[`"\']\s*\)'

        for match in re.finditer(import_pattern, self.content):
            result['dynamic_imports'].append({
                'path': match.group(1),
                'type': 'esm'
            })

    def _extract_require_calls(self, result: Dict):
        """Extract all require-like calls"""
        patterns = [
            r'require\s*\(\s*[`"\']([^`"\']+)[`"\']\s*\)',
            r'__webpack_require__\s*\(\s*[`"\']([^`"\']+)[`"\']\s*\)',
            r'__webpack_require__\.e\s*\(\s*(\d+)\s*\)',  # Chunk loading
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, self.content):
                result['require_calls'].append({
                    'target': match.group(1),
                    'pattern': pattern[:30]
                })

    def _extract_dynamic_imports(self, result: Dict):
        """Extract dynamic import statements"""
        patterns = [
            # import()
            r'import\s*\(\s*[`"\'/]([^`"\']+)[`"\']\s*\)',
            # require.ensure
            r'require\.ensure\s*\([^,]*,\s*function[^{]*\{[^}]*require\s*\(\s*[`"\']([^`"\']+)',
            # Next.js dynamic
            r'dynamic\s*\(\s*\(\s*\)\s*=>\s*import\s*\(\s*[`"\']([^`"\']+)',
            r'next/dynamic[^)]*\(\s*\(\s*\)\s*=>\s*import\s*\(\s*[`"\']([^`"\']+)',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, self.content):
                path = match.group(1)
                if path not in [d['path'] for d in result['dynamic_imports']]:
                    result['dynamic_imports'].append({
                        'path': path,
                        'pattern': 'dynamic'
                    })


class VariableTracker:
    """
    Tracks variable assignments and usage
    Resolves variable values when possible
    """

    def __init__(self, content: str):
        self.content = content
        self.variables: Dict[str, List[Dict]] = defaultdict(list)
        self.constants: Dict[str, str] = {}

    def track(self) -> Dict[str, Any]:
        """Track all variable assignments"""
        self._extract_const_let_var()
        self._extract_destructuring()
        self._extract_object_assignments()
        self._extract_function_params()

        return {
            'variables': dict(self.variables),
            'constants': self.constants,
            'url_variables': self._find_url_variables(),
            'api_variables': self._find_api_variables(),
            'config_variables': self._find_config_variables(),
        }

    def _extract_const_let_var(self):
        """Extract const/let/var declarations"""
        # const/let/var name = value
        pattern = r'(?:const|let|var)\s+(\w+)\s*=\s*([^;\n]+)'

        for match in re.finditer(pattern, self.content):
            name = match.group(1)
            value = match.group(2).strip()

            self.variables[name].append({
                'type': 'declaration',
                'value': value[:200],  # Truncate long values
                'resolved': self._try_resolve(value)
            })

    def _extract_destructuring(self):
        """Extract destructuring assignments"""
        # const { a, b } = obj
        pattern = r'(?:const|let|var)\s*\{\s*([^}]+)\}\s*=\s*(\w+)'

        for match in re.finditer(pattern, self.content):
            props = match.group(1)
            source = match.group(2)

            for prop in props.split(','):
                prop = prop.strip().split(':')[0].strip()
                if prop:
                    self.variables[prop].append({
                        'type': 'destructure',
                        'source': source
                    })

    def _extract_object_assignments(self):
        """Extract object property assignments"""
        # obj.prop = value
        pattern = r'(\w+)\.(\w+)\s*=\s*([^;\n]+)'

        for match in re.finditer(pattern, self.content):
            obj = match.group(1)
            prop = match.group(2)
            value = match.group(3).strip()

            key = f"{obj}.{prop}"
            self.variables[key].append({
                'type': 'property_assignment',
                'value': value[:200]
            })

    def _extract_function_params(self):
        """Extract function parameters that might be URLs"""
        # function name(url, endpoint, apiPath, etc)
        url_params = ['url', 'endpoint', 'path', 'api', 'uri', 'href', 'route']
        pattern = r'function\s+\w+\s*\(([^)]+)\)'

        for match in re.finditer(pattern, self.content):
            params = match.group(1)
            for param in params.split(','):
                param = param.strip().split('=')[0].strip()
                if any(up in param.lower() for up in url_params):
                    self.variables[param].append({
                        'type': 'function_param',
                        'hint': 'url_like'
                    })

    def _try_resolve(self, value: str) -> Optional[str]:
        """Try to resolve a value to a string"""
        # Remove quotes and return
        if value.startswith('"') or value.startswith("'"):
            return value.strip('"\'')
        if value.startswith('`'):
            # Template literal without variables
            if '${' not in value:
                return value.strip('`')
        return None

    def _find_url_variables(self) -> List[Dict]:
        """Find variables that look like URLs"""
        url_vars = []

        for name, assignments in self.variables.items():
            for assign in assignments:
                if 'value' in assign:
                    val = assign.get('resolved') or assign['value']
                    if isinstance(val, str):
                        if val.startswith('/') or val.startswith('http') or '/api' in val:
                            url_vars.append({
                                'name': name,
                                'value': val,
                                'type': assign['type']
                            })

        return url_vars

    def _find_api_variables(self) -> List[Dict]:
        """Find variables related to API"""
        api_keywords = ['api', 'endpoint', 'url', 'base', 'host', 'server', 'backend']
        api_vars = []

        for name, assignments in self.variables.items():
            if any(kw in name.lower() for kw in api_keywords):
                for assign in assignments:
                    api_vars.append({
                        'name': name,
                        'assignment': assign
                    })

        return api_vars

    def _find_config_variables(self) -> List[Dict]:
        """Find config-related variables"""
        config_keywords = ['config', 'settings', 'options', 'env', 'constants']
        config_vars = []

        for name, assignments in self.variables.items():
            if any(kw in name.lower() for kw in config_keywords):
                for assign in assignments:
                    config_vars.append({
                        'name': name,
                        'assignment': assign
                    })

        return config_vars


class ObjectDeepExtractor:
    """
    Extracts nested object structures from JavaScript
    Goes beyond simple regex to parse object literals
    """

    def __init__(self, content: str):
        self.content = content

    def extract_objects(self) -> List[Dict]:
        """Extract all meaningful objects"""
        objects = []

        # Find object assignments
        objects.extend(self._extract_assigned_objects())

        # Find config objects
        objects.extend(self._extract_config_objects())

        # Find API definition objects
        objects.extend(self._extract_api_objects())

        # Find route definition objects
        objects.extend(self._extract_route_objects())

        return objects

    def _extract_assigned_objects(self) -> List[Dict]:
        """Extract objects assigned to variables"""
        objects = []

        # Pattern: name = {...}
        pattern = r'(\w+)\s*=\s*(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})'

        for match in re.finditer(pattern, self.content):
            name = match.group(1)
            obj_str = match.group(2)

            parsed = self._parse_object(obj_str)
            if parsed:
                objects.append({
                    'name': name,
                    'properties': parsed,
                    'raw': obj_str[:500]
                })

        return objects

    def _extract_config_objects(self) -> List[Dict]:
        """Extract configuration objects"""
        configs = []

        # Common config patterns
        patterns = [
            r'(?:config|Config|CONFIG)\s*[=:]\s*(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})',
            r'(?:settings|Settings|SETTINGS)\s*[=:]\s*(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})',
            r'(?:options|Options|OPTIONS)\s*[=:]\s*(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})',
            r'getConfig\s*\(\s*\)\s*\{[^}]*return\s*(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, self.content, re.DOTALL):
                obj_str = match.group(1)
                parsed = self._parse_object(obj_str)
                if parsed:
                    configs.append({
                        'type': 'config',
                        'properties': parsed,
                        'raw': obj_str[:500]
                    })

        return configs

    def _extract_api_objects(self) -> List[Dict]:
        """Extract API definition objects"""
        apis = []

        patterns = [
            # endpoints: { users: '/api/users', ... }
            r'(?:endpoints?|apis?|routes?)\s*[=:]\s*(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})',
            # API = { BASE_URL: '...', endpoints: {...} }
            r'(?:API|Api)\s*=\s*(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, self.content, re.IGNORECASE | re.DOTALL):
                obj_str = match.group(1)
                parsed = self._parse_object(obj_str)
                if parsed:
                    apis.append({
                        'type': 'api_definition',
                        'properties': parsed,
                        'raw': obj_str[:500]
                    })

        return apis

    def _extract_route_objects(self) -> List[Dict]:
        """Extract route definition objects"""
        routes = []

        patterns = [
            # routes: [{path: '/', component: ...}]
            r'(?:routes?)\s*[=:]\s*(\[[^\[\]]*(?:\[[^\[\]]*\][^\[\]]*)*\])',
            # path: '/dashboard', element: <...>
            r'\{\s*path\s*:\s*["\']([^"\']+)["\'][^}]*\}',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, self.content):
                routes.append({
                    'type': 'route_definition',
                    'raw': match.group(1) if match.lastindex else match.group(0),
                })

        return routes

    def _parse_object(self, obj_str: str) -> Dict:
        """Parse object string into dictionary"""
        result = {}

        # Extract key-value pairs
        # key: value or "key": value or 'key': value
        kv_pattern = r'["\']?(\w+)["\']?\s*:\s*(["\'][^"\']*["\']|[\d.]+|true|false|null|\[[^\]]*\]|\{[^}]*\})'

        for match in re.finditer(kv_pattern, obj_str):
            key = match.group(1)
            value = match.group(2)

            # Clean value
            if value.startswith('"') or value.startswith("'"):
                value = value.strip('"\'')

            result[key] = value

        return result


class StringConcatenationResolver:
    """
    Resolves string concatenation to find complete URLs
    Handles: baseUrl + "/api" + endpoint
    """

    def __init__(self, content: str, variables: Dict[str, Any]):
        self.content = content
        self.variables = variables

    def resolve(self) -> List[Dict]:
        """Find and resolve string concatenations"""
        resolved = []

        # Pattern: str + str + str
        concat_pattern = r'(["\'][^"\']*["\']|\w+)(?:\s*\+\s*(["\'][^"\']*["\']|\w+))+'

        for match in re.finditer(concat_pattern, self.content):
            full_match = match.group(0)
            parts = re.split(r'\s*\+\s*', full_match)

            resolved_parts = []
            has_url_part = False

            for part in parts:
                part = part.strip()
                if part.startswith('"') or part.startswith("'"):
                    resolved_parts.append(part.strip('"\''))
                    if '/' in part or 'api' in part.lower():
                        has_url_part = True
                else:
                    # Try to resolve variable
                    var_value = self._resolve_variable(part)
                    if var_value:
                        resolved_parts.append(var_value)
                        if '/' in var_value or 'http' in var_value:
                            has_url_part = True
                    else:
                        resolved_parts.append(f'${{{part}}}')

            if has_url_part:
                resolved.append({
                    'original': full_match,
                    'resolved': ''.join(resolved_parts),
                    'parts': resolved_parts
                })

        return resolved

    def _resolve_variable(self, name: str) -> Optional[str]:
        """Try to resolve a variable name to its value"""
        if name in self.variables:
            assigns = self.variables[name]
            for assign in assigns:
                if 'resolved' in assign and assign['resolved']:
                    return assign['resolved']
                if 'value' in assign:
                    val = assign['value']
                    if val.startswith('"') or val.startswith("'"):
                        return val.strip('"\'')
        return None


class TemplateLiteralExtractor:
    """
    Extracts and partially resolves template literals
    Handles: `${baseUrl}/api/${endpoint}`
    """

    def __init__(self, content: str, variables: Dict[str, Any]):
        self.content = content
        self.variables = variables

    def extract(self) -> List[Dict]:
        """Extract template literals with URL patterns"""
        templates = []

        # Find template literals
        pattern = r'`([^`]*\$\{[^`]*)`'

        for match in re.finditer(pattern, self.content):
            template = match.group(1)

            # Check if it looks like a URL
            if '/' in template or 'api' in template.lower() or 'http' in template.lower():
                # Extract variable names
                vars_in_template = re.findall(r'\$\{([^}]+)\}', template)

                # Try to resolve
                resolved = template
                for var in vars_in_template:
                    var_value = self._resolve_variable(var)
                    if var_value:
                        resolved = resolved.replace(f'${{{var}}}', var_value)

                templates.append({
                    'original': template,
                    'resolved': resolved,
                    'variables': vars_in_template,
                    'is_url': self._is_url_like(resolved)
                })

        return templates

    def _resolve_variable(self, name: str) -> Optional[str]:
        """Resolve variable, handling property access"""
        # Handle property access: config.apiUrl
        if '.' in name:
            parts = name.split('.')
            # Try to find in nested objects
            # For now, return None for complex cases
            return None

        if name in self.variables:
            for assign in self.variables[name]:
                if 'resolved' in assign:
                    return assign['resolved']
        return None

    def _is_url_like(self, s: str) -> bool:
        """Check if string looks like a URL"""
        url_indicators = ['/api', '/v1', '/v2', 'http', '/graphql', '/auth', '/webhook']
        return any(ind in s.lower() for ind in url_indicators)


class FunctionCallTracer:
    """
    Traces function calls to find URL-related invocations
    """

    def __init__(self, content: str):
        self.content = content

    def trace(self) -> List[Dict]:
        """Trace all function calls with URL-like arguments"""
        calls = []

        # HTTP client calls
        calls.extend(self._trace_http_calls())

        # Next.js specific calls
        calls.extend(self._trace_nextjs_calls())

        # Generic fetch/request calls
        calls.extend(self._trace_generic_calls())

        # Router calls
        calls.extend(self._trace_router_calls())

        return calls

    def _trace_http_calls(self) -> List[Dict]:
        """Trace HTTP client calls"""
        calls = []

        patterns = [
            # axios.method(url, ...)
            (r'axios\.(\w+)\s*\(\s*([^,)]+)', 'axios'),
            # fetch(url, options)
            (r'fetch\s*\(\s*([^,)]+)', 'fetch'),
            # http.get/post/etc
            (r'http\.(\w+)\s*\(\s*([^,)]+)', 'http'),
            # request(options)
            (r'request\s*\(\s*\{[^}]*url\s*:\s*([^,}]+)', 'request'),
            # ky.get/post
            (r'ky\.(\w+)\s*\(\s*([^,)]+)', 'ky'),
            # got(url)
            (r'got(?:\.(\w+))?\s*\(\s*([^,)]+)', 'got'),
            # superagent
            (r'superagent\.(\w+)\s*\(\s*([^,)]+)', 'superagent'),
        ]

        for pattern, lib in patterns:
            for match in re.finditer(pattern, self.content):
                method = match.group(1) if match.lastindex > 1 else 'default'
                url = match.group(match.lastindex).strip()

                calls.append({
                    'type': 'http_client',
                    'library': lib,
                    'method': method,
                    'url_argument': url[:200],
                    'is_dynamic': '${' in url or '+' in url or url.startswith('`')
                })

        return calls

    def _trace_nextjs_calls(self) -> List[Dict]:
        """Trace Next.js specific function calls"""
        calls = []

        patterns = [
            # getServerSideProps fetch
            (r'getServerSideProps[^}]*fetch\s*\(\s*([^,)]+)', 'getServerSideProps'),
            # getStaticProps fetch
            (r'getStaticProps[^}]*fetch\s*\(\s*([^,)]+)', 'getStaticProps'),
            # Server Actions
            (r'"use server"[^}]*fetch\s*\(\s*([^,)]+)', 'serverAction'),
            # API route handler
            (r'export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH)', 'apiRoute'),
            # revalidatePath
            (r'revalidatePath\s*\(\s*([^)]+)', 'revalidatePath'),
            # redirect
            (r'redirect\s*\(\s*([^)]+)', 'redirect'),
        ]

        for pattern, fn_type in patterns:
            for match in re.finditer(pattern, self.content, re.DOTALL):
                calls.append({
                    'type': 'nextjs',
                    'function': fn_type,
                    'argument': match.group(1)[:200] if match.lastindex else 'N/A'
                })

        return calls

    def _trace_generic_calls(self) -> List[Dict]:
        """Trace generic function calls with URL arguments"""
        calls = []

        # Functions that commonly receive URLs
        url_functions = [
            'fetchData', 'getData', 'postData', 'sendRequest', 'makeRequest',
            'apiCall', 'callApi', 'request', 'get', 'post', 'put', 'delete',
            'loadData', 'fetchJson', 'getJson', 'apiRequest', 'httpRequest',
        ]

        for fn in url_functions:
            pattern = rf'\b{fn}\s*\(\s*([^,)]+)'
            for match in re.finditer(pattern, self.content):
                arg = match.group(1).strip()
                # Filter out obvious non-URLs
                if not arg.startswith('function') and not arg.startswith('{'):
                    calls.append({
                        'type': 'generic',
                        'function': fn,
                        'argument': arg[:200]
                    })

        return calls

    def _trace_router_calls(self) -> List[Dict]:
        """Trace router navigation calls"""
        calls = []

        patterns = [
            # Next.js router
            (r'router\.push\s*\(\s*([^,)]+)', 'push'),
            (r'router\.replace\s*\(\s*([^,)]+)', 'replace'),
            (r'Router\.push\s*\(\s*([^,)]+)', 'push'),
            (r'Router\.replace\s*\(\s*([^,)]+)', 'replace'),
            # useRouter hook
            (r'useRouter\s*\(\s*\).*?\.push\s*\(\s*([^,)]+)', 'push'),
            # React Router
            (r'navigate\s*\(\s*([^,)]+)', 'navigate'),
            (r'history\.push\s*\(\s*([^,)]+)', 'push'),
        ]

        for pattern, action in patterns:
            for match in re.finditer(pattern, self.content, re.DOTALL):
                route = match.group(1).strip()
                calls.append({
                    'type': 'router',
                    'action': action,
                    'route': route[:200]
                })

        return calls


class HiddenEndpointFinder:
    """
    Finds hidden/undocumented endpoints through various techniques
    """

    def __init__(self, content: str):
        self.content = content

    def find(self) -> List[Dict]:
        """Find hidden endpoints"""
        endpoints = []

        # Admin/internal endpoints
        endpoints.extend(self._find_admin_endpoints())

        # Debug endpoints
        endpoints.extend(self._find_debug_endpoints())

        # Internal APIs
        endpoints.extend(self._find_internal_apis())

        # Hidden routes from comments
        endpoints.extend(self._find_commented_endpoints())

        # Conditional endpoints (feature flags)
        endpoints.extend(self._find_conditional_endpoints())

        # Environment-specific endpoints
        endpoints.extend(self._find_env_endpoints())

        return endpoints

    def _find_admin_endpoints(self) -> List[Dict]:
        """Find admin-related endpoints"""
        endpoints = []

        patterns = [
            r'["\'/](admin[^\s"\']*)["\']',
            r'["\'/](internal[^\s"\']*)["\']',
            r'["\'/](manage[^\s"\']*)["\']',
            r'["\'/](dashboard[^\s"\']*)["\']',
            r'["\'/](control[^\s"\']*)["\']',
            r'["\'/](_[a-z]+[^\s"\']*)["\']',  # Underscore prefixed
            r'["\'/](backoffice[^\s"\']*)["\']',
            r'["\'/](superuser[^\s"\']*)["\']',
            r'["\'/](moderator[^\s"\']*)["\']',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, self.content, re.IGNORECASE):
                path = match.group(1)
                if len(path) > 3 and not path.endswith('.js') and not path.endswith('.css'):
                    endpoints.append({
                        'type': 'admin',
                        'path': '/' + path.lstrip('/'),
                        'confidence': 'medium'
                    })

        return endpoints

    def _find_debug_endpoints(self) -> List[Dict]:
        """Find debug-related endpoints"""
        endpoints = []

        patterns = [
            r'["\'/](debug[^\s"\']*)["\']',
            r'["\'/](test[^\s"\']*)["\']',
            r'["\'/](dev[^\s"\']*)["\']',
            r'["\'/](staging[^\s"\']*)["\']',
            r'["\'/](sandbox[^\s"\']*)["\']',
            r'["\'/](mock[^\s"\']*)["\']',
            r'["\'/](trace[^\s"\']*)["\']',
            r'["\'/](log[^\s"\']*)["\']',
            r'["\'/](metrics[^\s"\']*)["\']',
            r'["\'/](health[^\s"\']*)["\']',
            r'["\'/](status[^\s"\']*)["\']',
            r'["\'/](info[^\s"\']*)["\']',
            r'["\'/](version[^\s"\']*)["\']',
            r'["\'/](ping[^\s"\']*)["\']',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, self.content, re.IGNORECASE):
                path = match.group(1)
                if len(path) > 3 and not path.endswith('.js'):
                    endpoints.append({
                        'type': 'debug',
                        'path': '/' + path.lstrip('/'),
                        'confidence': 'medium'
                    })

        return endpoints

    def _find_internal_apis(self) -> List[Dict]:
        """Find internal API endpoints"""
        endpoints = []

        patterns = [
            # Internal API patterns
            r'["\']/(api/internal[^\s"\']*)["\']',
            r'["\']/(api/private[^\s"\']*)["\']',
            r'["\']/(api/v\d+/internal[^\s"\']*)["\']',
            r'["\']/(api/admin[^\s"\']*)["\']',
            r'["\']/(api/_[^\s"\']*)["\']',  # Underscore prefixed
            # GraphQL mutations that might be internal
            r'mutation\s+(\w*[Ii]nternal\w*)',
            r'mutation\s+(\w*[Aa]dmin\w*)',
            r'mutation\s+(\w*[Dd]elete\w*)',
            r'mutation\s+(\w*[Uu]pdate\w*)',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, self.content):
                path = match.group(1)
                endpoints.append({
                    'type': 'internal_api',
                    'path': path if path.startswith('/') else f'mutation:{path}',
                    'confidence': 'high'
                })

        return endpoints

    def _find_commented_endpoints(self) -> List[Dict]:
        """Find endpoints in comments"""
        endpoints = []

        # Single line comments
        comment_pattern = r'//[^\n]*(/api/[^\s\n]+|/v\d+/[^\s\n]+)'
        for match in re.finditer(comment_pattern, self.content):
            endpoints.append({
                'type': 'commented',
                'path': match.group(1),
                'confidence': 'low'
            })

        # Multi-line comments
        ml_comment_pattern = r'/\*[^*]*\*+(?:[^/*][^*]*\*+)*/'
        for match in re.finditer(ml_comment_pattern, self.content):
            comment = match.group(0)
            for api_match in re.finditer(r'(/api/[^\s*]+|/v\d+/[^\s*]+)', comment):
                endpoints.append({
                    'type': 'commented',
                    'path': api_match.group(1),
                    'confidence': 'low'
                })

        return endpoints

    def _find_conditional_endpoints(self) -> List[Dict]:
        """Find endpoints behind feature flags"""
        endpoints = []

        # Pattern: if (featureFlag) { ... /api/... }
        patterns = [
            r'if\s*\([^)]*(?:feature|flag|enabled|beta|canary)[^)]*\)[^{]*\{[^}]*["\']([/\w]+)["\']',
            r'(?:feature|flag|enabled)\s*\?\s*["\']([/\w]+)["\']',
            r'process\.env\.(?:FEATURE|FLAG|ENABLE)[^}]*["\']([/\w]+)["\']',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, self.content, re.IGNORECASE):
                path = match.group(1)
                if '/' in path:
                    endpoints.append({
                        'type': 'feature_flag',
                        'path': path,
                        'confidence': 'medium'
                    })

        return endpoints

    def _find_env_endpoints(self) -> List[Dict]:
        """Find environment-specific endpoints"""
        endpoints = []

        patterns = [
            r'process\.env\.(\w*URL\w*)',
            r'process\.env\.(\w*API\w*)',
            r'process\.env\.(\w*ENDPOINT\w*)',
            r'process\.env\.(\w*HOST\w*)',
            r'import\.meta\.env\.(\w*URL\w*)',
            r'import\.meta\.env\.(\w*API\w*)',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, self.content):
                env_var = match.group(1)
                endpoints.append({
                    'type': 'env_variable',
                    'env_var': env_var,
                    'confidence': 'medium'
                })

        return endpoints


class DeepExtractor:
    """
    Main class that orchestrates all deep extraction
    """

    def __init__(self, target: str, output_dir: str = ".", verbose: bool = False):
        self.target = target.rstrip('/')
        self.output_dir = output_dir
        self.verbose = verbose

        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.session.verify = False

        self.js_files: Dict[str, str] = {}
        self.findings: List[DeepFinding] = []
        self.stats = defaultdict(int)

    def log(self, level: str, msg: str):
        colors = {
            'info': Colors.BLUE,
            'success': Colors.GREEN,
            'warning': Colors.YELLOW,
            'critical': Colors.RED,
            'deep': Colors.PURPLE,
            'finding': Colors.CYAN,
        }
        color = colors.get(level, '')
        print(f"{color}[{level.upper()}]{Colors.END} {msg}")

    def run(self):
        """Run deep extraction"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.PURPLE}   DEEP EXTRACTOR v1.0 - Beyond Regex{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"Target: {self.target}")
        print(f"Time: {datetime.now().isoformat()}")
        print()

        # Step 1: Collect JavaScript files
        self._collect_js_files()

        if not self.js_files:
            self.log('warning', 'No JavaScript files found')
            return

        # Step 2: Run deep extraction on each file
        for url, content in self.js_files.items():
            self._analyze_file(url, content)

        # Step 3: Cross-file analysis
        self._cross_file_analysis()

        # Step 4: Generate report
        self._generate_report()

        return self.findings

    def _collect_js_files(self):
        """Collect JavaScript files from target"""
        self.log('info', 'Collecting JavaScript files...')

        try:
            resp = self.session.get(self.target, timeout=30)
            html = resp.text

            # Find JS URLs
            js_patterns = [
                r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
                r'"([^"]+/_next/static/[^"]+\.js)"',
                r"'([^']+/_next/static/[^']+\.js)'",
            ]

            js_urls = set()
            for pattern in js_patterns:
                for match in re.findall(pattern, html):
                    url = urljoin(self.target, match)
                    js_urls.add(url)

            self.log('info', f'Found {len(js_urls)} JavaScript files')

            # Download files
            for url in list(js_urls)[:50]:  # Limit to 50 files
                try:
                    resp = self.session.get(url, timeout=20)
                    if resp.status_code == 200 and len(resp.text) > 100:
                        self.js_files[url] = resp.text
                        self.stats['js_files'] += 1
                except:
                    pass

            self.log('success', f'Downloaded {len(self.js_files)} JavaScript files')

        except Exception as e:
            self.log('warning', f'Error collecting JS: {e}')

    def _analyze_file(self, url: str, content: str):
        """Run all deep extractors on a file"""
        filename = url.split('/')[-1]

        if self.verbose:
            self.log('info', f'Analyzing: {filename}')

        # 1. Webpack Bundle Parser
        webpack = WebpackBundleParser(content, url)
        webpack_data = webpack.parse()

        if webpack_data.get('modules'):
            self.stats['webpack_modules'] += len(webpack_data['modules'])
        if webpack_data.get('dynamic_imports'):
            for imp in webpack_data['dynamic_imports']:
                self._add_finding(DeepFinding(
                    type='dynamic_import',
                    value=imp['path'],
                    source_file=filename,
                    context='Webpack dynamic import',
                    confidence='high',
                    extraction_method='webpack_parser',
                    metadata=imp
                ))

        # 2. Variable Tracker
        tracker = VariableTracker(content)
        vars_data = tracker.track()

        for url_var in vars_data.get('url_variables', []):
            self._add_finding(DeepFinding(
                type='url_variable',
                value=url_var['value'],
                source_file=filename,
                context=f"Variable: {url_var['name']}",
                confidence='high',
                extraction_method='variable_tracker',
                metadata=url_var
            ))

        for api_var in vars_data.get('api_variables', []):
            self._add_finding(DeepFinding(
                type='api_variable',
                value=str(api_var.get('assignment', {})),
                source_file=filename,
                context=f"API Variable: {api_var['name']}",
                confidence='medium',
                extraction_method='variable_tracker',
                metadata=api_var
            ))

        # 3. Object Deep Extractor
        obj_extractor = ObjectDeepExtractor(content)
        objects = obj_extractor.extract_objects()

        for obj in objects:
            if obj.get('type') in ['api_definition', 'config']:
                self._add_finding(DeepFinding(
                    type='config_object',
                    value=str(obj.get('properties', {}))[:500],
                    source_file=filename,
                    context=f"Object: {obj.get('name', 'anonymous')}",
                    confidence='high',
                    extraction_method='object_extractor',
                    metadata=obj
                ))

        # 4. String Concatenation Resolver
        resolver = StringConcatenationResolver(content, vars_data.get('variables', {}))
        concatenations = resolver.resolve()

        for concat in concatenations:
            if '/api' in concat['resolved'] or 'http' in concat['resolved']:
                self._add_finding(DeepFinding(
                    type='resolved_url',
                    value=concat['resolved'],
                    source_file=filename,
                    context=f"Concatenation: {concat['original'][:100]}",
                    confidence='medium',
                    extraction_method='concatenation_resolver',
                    metadata=concat
                ))

        # 5. Template Literal Extractor
        template_extractor = TemplateLiteralExtractor(content, vars_data.get('variables', {}))
        templates = template_extractor.extract()

        for template in templates:
            if template.get('is_url'):
                self._add_finding(DeepFinding(
                    type='template_url',
                    value=template['resolved'],
                    source_file=filename,
                    context=f"Template: {template['original'][:100]}",
                    confidence='medium',
                    extraction_method='template_extractor',
                    metadata=template
                ))

        # 6. Function Call Tracer
        tracer = FunctionCallTracer(content)
        calls = tracer.trace()

        for call in calls:
            if call['type'] == 'http_client':
                self._add_finding(DeepFinding(
                    type='http_call',
                    value=call['url_argument'],
                    source_file=filename,
                    context=f"{call['library']}.{call['method']}()",
                    confidence='high',
                    extraction_method='function_tracer',
                    metadata=call
                ))
            elif call['type'] == 'nextjs':
                self._add_finding(DeepFinding(
                    type='nextjs_call',
                    value=call.get('argument', 'N/A'),
                    source_file=filename,
                    context=f"Next.js {call['function']}",
                    confidence='high',
                    extraction_method='function_tracer',
                    metadata=call
                ))
            elif call['type'] == 'router':
                self._add_finding(DeepFinding(
                    type='router_navigation',
                    value=call['route'],
                    source_file=filename,
                    context=f"Router {call['action']}",
                    confidence='high',
                    extraction_method='function_tracer',
                    metadata=call
                ))

        # 7. Hidden Endpoint Finder
        finder = HiddenEndpointFinder(content)
        hidden = finder.find()

        for endpoint in hidden:
            self._add_finding(DeepFinding(
                type='hidden_endpoint',
                value=endpoint['path'],
                source_file=filename,
                context=f"Type: {endpoint['type']}",
                confidence=endpoint['confidence'],
                extraction_method='hidden_finder',
                metadata=endpoint
            ))

    def _add_finding(self, finding: DeepFinding):
        """Add a finding, avoiding duplicates"""
        # Simple dedup by value
        for existing in self.findings:
            if existing.value == finding.value and existing.type == finding.type:
                return

        self.findings.append(finding)
        self.stats[finding.type] += 1

    def _cross_file_analysis(self):
        """Analyze patterns across all files"""
        self.log('info', 'Running cross-file analysis...')

        # Find API base URLs used across files
        base_urls = defaultdict(int)
        for finding in self.findings:
            if finding.type in ['url_variable', 'http_call', 'resolved_url']:
                value = finding.value
                # Extract base URL
                if value.startswith('http'):
                    parsed = urlparse(value)
                    base = f"{parsed.scheme}://{parsed.netloc}"
                    base_urls[base] += 1
                elif value.startswith('/'):
                    parts = value.split('/')
                    if len(parts) > 2:
                        base = '/' + parts[1]
                        base_urls[base] += 1

        if base_urls:
            self.log('deep', f'Common API bases: {dict(list(base_urls.items())[:5])}')

    def _generate_report(self):
        """Generate extraction report"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.PURPLE}   DEEP EXTRACTION RESULTS{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")

        print(f"\n{Colors.CYAN}Statistics:{Colors.END}")
        for key, value in sorted(self.stats.items()):
            print(f"  {key}: {value}")

        # Group findings by type
        by_type = defaultdict(list)
        for finding in self.findings:
            by_type[finding.type].append(finding)

        print(f"\n{Colors.CYAN}Findings by Type:{Colors.END}")
        for ftype, findings in sorted(by_type.items()):
            print(f"\n{Colors.YELLOW}[{ftype.upper()}] ({len(findings)} found){Colors.END}")
            for f in findings[:10]:  # Show top 10 per type
                conf_color = Colors.GREEN if f.confidence == 'high' else Colors.YELLOW if f.confidence == 'medium' else Colors.DIM
                print(f"  {conf_color}[{f.confidence}]{Colors.END} {f.value[:80]}")
                if self.verbose:
                    print(f"       Source: {f.source_file}")
                    print(f"       Method: {f.extraction_method}")
            if len(findings) > 10:
                print(f"  ... and {len(findings) - 10} more")

        # Save to file
        report_dir = os.path.join(self.output_dir, 'deep_extraction')
        os.makedirs(report_dir, exist_ok=True)

        report = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'stats': dict(self.stats),
            'findings': [
                {
                    'type': f.type,
                    'value': f.value,
                    'source_file': f.source_file,
                    'context': f.context,
                    'confidence': f.confidence,
                    'extraction_method': f.extraction_method,
                    'metadata': f.metadata,
                }
                for f in self.findings
            ]
        }

        report_file = os.path.join(report_dir, 'deep_extraction_report.json')
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n{Colors.GREEN}Report saved to: {report_file}{Colors.END}")

        # Also save unique endpoints
        endpoints = set()
        for f in self.findings:
            if f.type in ['url_variable', 'http_call', 'hidden_endpoint', 'router_navigation', 'resolved_url']:
                value = f.value
                if value.startswith('/') or value.startswith('http'):
                    # Clean up
                    value = value.split('?')[0].split('#')[0]
                    if len(value) > 2:
                        endpoints.add(value)

        endpoints_file = os.path.join(report_dir, 'extracted_endpoints.txt')
        with open(endpoints_file, 'w') as f:
            for ep in sorted(endpoints):
                f.write(ep + '\n')

        print(f"{Colors.GREEN}Endpoints saved to: {endpoints_file}{Colors.END}")
        print(f"Total unique endpoints: {len(endpoints)}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python deep_extractor.py <target_url> [-v]")
        print("Example: python deep_extractor.py https://example.com -v")
        sys.exit(1)

    target = sys.argv[1]
    verbose = '-v' in sys.argv or '--verbose' in sys.argv

    extractor = DeepExtractor(target, verbose=verbose)
    extractor.run()


if __name__ == "__main__":
    main()
