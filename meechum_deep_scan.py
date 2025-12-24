import subprocess
import re
import string
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

print("=" * 70)
print("MEECHUM CDN DEEP SCAN")
print("=" * 70)

base_url = "https://meechum.prod.netflix.net/cdn/"

# Known working hash pattern: de89b324952c03796a64 (20 hex chars)
# Try to find other bundles

# Common webpack chunk names
chunk_names = [
    "bundle", "main", "vendor", "app", "chunk", "runtime",
    "polyfills", "scripts", "styles", "framework", "commons",
    "webpack", "pages", "components", "core", "shared", "utils",
    "index", "admitone", "client", "server", "api"
]

# Try direct paths first
print("\n[1] Trying common bundle names...")
direct_paths = [
    "bundle.js",
    "bundle.js.map",
    "main.js",
    "main.js.map",
    "app.js",
    "app.js.map",
    "vendor.js",
    "vendor.js.map",
    "index.js",
    "index.js.map",
    "admitone.js",
    "admitone.js.map",
    "client.js",
    "client.js.map",
    "webpack.js",
    "webpack.js.map",
    "runtime.js",
    "runtime.js.map",
]

for path in direct_paths:
    url = base_url + path
    try:
        r = subprocess.run(
            ['curl', '-s', '-o', 'NUL', '-w', '%{http_code}', '-I', url],
            capture_output=True, text=True, timeout=10
        )
        code = r.stdout.strip()
        if code == '200':
            print(f"  [FOUND] {url}")
        elif code not in ['403', '404', '000']:
            print(f"  [{code}] {path}")
    except:
        pass

# Try to enumerate files using S3 patterns
print("\n[2] Trying S3 bucket listing patterns...")
s3_patterns = [
    "?list-type=2",
    "?prefix=",
    "?delimiter=/",
    "?max-keys=1000",
]

for pattern in s3_patterns:
    url = base_url + pattern
    try:
        r = subprocess.run(
            ['curl', '-s', '--max-time', '10', url],
            capture_output=True, text=True, timeout=15
        )
        if '<Key>' in r.stdout or '<Contents>' in r.stdout:
            print(f"  [LISTING FOUND] {url}")
            print(r.stdout[:500])
    except:
        pass

# Try root paths
print("\n[3] Checking meechum.prod.netflix.net paths...")
meechum_paths = [
    "/",
    "/assets/",
    "/static/",
    "/js/",
    "/dist/",
    "/build/",
    "/.well-known/",
    "/api/",
    "/graphql",
    "/health",
    "/status",
    "/version",
    "/config",
    "/manifest.json",
    "/robots.txt",
    "/sitemap.xml",
]

base_meechum = "https://meechum.prod.netflix.net"
for path in meechum_paths:
    url = base_meechum + path
    try:
        r = subprocess.run(
            ['curl', '-s', '-o', 'NUL', '-w', '%{http_code}', '--max-time', '5', url],
            capture_output=True, text=True, timeout=10
        )
        code = r.stdout.strip()
        if code == '200':
            print(f"  [200] {path}")
        elif code in ['301', '302', '307', '308']:
            print(f"  [REDIRECT] {path}")
        elif code not in ['403', '404', '000']:
            print(f"  [{code}] {path}")
    except:
        pass

# Check also meechum.netflix.com (non-prod)
print("\n[4] Checking meechum.netflix.com (staging?)...")
base_staging = "https://meechum.netflix.com"
for path in ["/", "/cdn/", "/cdn/bundle.js", "/cdn/bundle.js.map"]:
    url = base_staging + path
    try:
        r = subprocess.run(
            ['curl', '-s', '-o', 'NUL', '-w', '%{http_code}', '--max-time', '5', url],
            capture_output=True, text=True, timeout=10
        )
        code = r.stdout.strip()
        print(f"  [{code}] {path}")
    except:
        pass

# Try to find build manifest
print("\n[5] Looking for build manifests...")
manifest_paths = [
    "/cdn/asset-manifest.json",
    "/cdn/manifest.json",
    "/cdn/webpack-manifest.json",
    "/cdn/build-manifest.json",
    "/cdn/precache-manifest.js",
    "/cdn/workbox-manifest.js",
    "/cdn/stats.json",
    "/cdn/webpack-stats.json",
]

for path in manifest_paths:
    url = base_meechum + path
    try:
        r = subprocess.run(
            ['curl', '-s', '--max-time', '5', url],
            capture_output=True, text=True, timeout=10
        )
        if r.stdout and len(r.stdout) > 10 and '{' in r.stdout:
            print(f"  [FOUND] {path}")
            print(f"    Content: {r.stdout[:200]}...")
            # Save it
            filename = path.split('/')[-1]
            with open(f"C:\\Users\\gokim\\netflix-recon\\js-files\\{filename}", 'w') as f:
                f.write(r.stdout)
    except:
        pass

print("\n" + "=" * 70)
print("Scan complete!")
