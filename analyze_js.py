import re
import json

with open(r'C:\Users\gokim\netflix-recon\js-files\nmhpFrameworkClient.js', 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

print("=== API Endpoints ===")
# Find API paths
api_patterns = [
    r'["\']/(api|graphql|v[0-9]+)/[a-zA-Z0-9/_-]+["\']',
    r'["\']https?://[^"\']*api[^"\']+["\']',
    r'fetch\(["\']([^"\']+)["\']',
]

for pattern in api_patterns:
    matches = re.findall(pattern, content)
    for m in set(matches)[:15]:
        print(m)

print("\n=== Potential Secrets ===")
secret_patterns = [
    (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'API Key'),
    (r'["\']?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'Token'),
    (r'["\']?secret["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Secret'),
    (r'["\']?password["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Password'),
    (r'(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)', 'JWT'),
    (r'["\']([A-Z0-9]{20})["\']', 'AWS Key like'),
]

for pattern, name in secret_patterns:
    matches = re.findall(pattern, content, re.IGNORECASE)
    for m in set(matches)[:5]:
        print(f"{name}: {m[:50]}...")

print("\n=== Internal URLs ===")
internal_patterns = [
    r'https?://[a-zA-Z0-9._-]*(staging|internal|dev|test|admin|debug)[a-zA-Z0-9._/-]*',
]
for pattern in internal_patterns:
    matches = re.findall(pattern, content, re.IGNORECASE)
    for m in set(matches)[:10]:
        print(m)

print("\n=== Interesting Functions ===")
func_patterns = [
    r'function\s+(auth[a-zA-Z0-9_]*)',
    r'function\s+(login[a-zA-Z0-9_]*)',
    r'function\s+(validate[a-zA-Z0-9_]*)',
    r'function\s+(check[a-zA-Z0-9_]*)',
]
for pattern in func_patterns:
    matches = re.findall(pattern, content, re.IGNORECASE)
    for m in set(matches)[:5]:
        print(m)
