import re
from collections import Counter

with open(r'C:\Users\gokim\netflix-recon\gau_urls.txt', 'r', encoding='utf-8', errors='ignore') as f:
    urls = f.readlines()

print(f"Total URLs: {len(urls)}")

# Find interesting patterns
interesting_keywords = ['api', 'admin', 'internal', 'debug', 'test', 'staging',
                        'dev', 'config', 'secret', 'token', 'auth', 'login',
                        'graphql', 'webhook', 'callback', 'upload', 'download',
                        'backup', 'export', 'import', 'private', 'hidden']

print("\n=== Interesting URLs ===")
interesting = []
for url in urls:
    url = url.strip()
    for kw in interesting_keywords:
        if kw in url.lower():
            interesting.append(url)
            break

for url in sorted(set(interesting))[:50]:
    print(url)

# Find API endpoints
print("\n=== API Endpoints ===")
api_urls = [u.strip() for u in urls if '/api/' in u.lower() or 'api.' in u.lower()]
for url in sorted(set(api_urls))[:30]:
    print(url)

# Find parameters
print("\n=== Unique Parameters ===")
params = []
for url in urls:
    matches = re.findall(r'[?&]([a-zA-Z0-9_]+)=', url)
    params.extend(matches)

param_counts = Counter(params)
for param, count in param_counts.most_common(30):
    print(f"{param}: {count}")

# Find file extensions
print("\n=== Interesting File Types ===")
extensions = ['json', 'xml', 'yaml', 'yml', 'conf', 'config', 'env', 'bak', 'old', 'sql', 'log']
for ext in extensions:
    matching = [u.strip() for u in urls if f'.{ext}' in u.lower()]
    if matching:
        print(f"\n.{ext} files ({len(matching)}):")
        for url in matching[:5]:
            print(f"  {url}")
