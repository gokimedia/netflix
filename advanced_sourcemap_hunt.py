import subprocess
import re
import os
import base64
import json

print("=" * 70)
print("ADVANCED SOURCE MAP HUNTER")
print("=" * 70)

# 1. Check downloaded JS files for inline/external source maps
print("\n[1] Checking downloaded JS files for sourceMappingURL...")
js_dir = r"C:\Users\gokim\netflix-recon\js-files"
for filename in os.listdir(js_dir):
    if filename.endswith('.js'):
        filepath = os.path.join(js_dir, filename)
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

                # Check for sourceMappingURL
                map_match = re.search(r'//[#@]\s*sourceMappingURL=([^\s]+)', content)
                if map_match:
                    map_ref = map_match.group(1)
                    if map_ref.startswith('data:'):
                        print(f"  [INLINE] {filename}: Base64 encoded source map found!")
                        # Extract and decode
                        base64_data = re.search(r'base64,(.+)', map_ref)
                        if base64_data:
                            try:
                                decoded = base64.b64decode(base64_data.group(1))
                                print(f"    Size: {len(decoded)} bytes")
                                # Save it
                                map_path = filepath + ".decoded.map"
                                with open(map_path, 'wb') as mf:
                                    mf.write(decoded)
                                print(f"    Saved to: {map_path}")
                            except:
                                print(f"    Failed to decode")
                    else:
                        print(f"  [EXTERNAL] {filename}: {map_ref}")
        except Exception as e:
            print(f"  Error reading {filename}: {e}")

# 2. Fetch research.netflix.com JS files
print("\n[2] Fetching research.netflix.com JS files...")
try:
    r = subprocess.run(
        ['curl', '-s', '-L', 'https://research.netflix.com'],
        capture_output=True, text=True, timeout=30, encoding='utf-8', errors='ignore'
    )
    html = r.stdout

    # Find all _next JS chunks
    js_files = re.findall(r'/_next/static/chunks/([^"\']+\.js)', html)
    js_files += re.findall(r'/_next/static/[^/]+/([^"\']+\.js)', html)
    js_files = list(set(js_files))

    print(f"  Found {len(js_files)} JS chunks")

    for js in js_files[:10]:
        print(f"  - {js}")

    # Try to find buildId
    build_match = re.search(r'/_next/static/([a-zA-Z0-9_-]{20,})', html)
    if build_match:
        build_id = build_match.group(1)
        print(f"\n  Build ID: {build_id}")

        # Try common source map patterns
        patterns = [
            f"https://research.netflix.com/_next/static/{build_id}/_ssgManifest.js.map",
            f"https://research.netflix.com/_next/static/{build_id}/_buildManifest.js.map",
            f"https://research.netflix.com/_next/static/chunks/webpack.js.map",
            f"https://research.netflix.com/_next/static/chunks/main.js.map",
            f"https://research.netflix.com/_next/static/chunks/pages/_app.js.map",
        ]

        for pattern in patterns:
            try:
                pr = subprocess.run(
                    ['curl', '-s', '-o', 'NUL', '-w', '%{http_code}', '-I', pattern],
                    capture_output=True, text=True, timeout=10
                )
                code = pr.stdout.strip()
                if code == '200':
                    print(f"    [FOUND!] {pattern}")
                elif code not in ['403', '404']:
                    print(f"    [{code}] {pattern}")
            except:
                pass
except Exception as e:
    print(f"  Error: {e}")

# 3. Check jobs.netflix.com
print("\n[3] Fetching jobs.netflix.com JS files...")
try:
    r = subprocess.run(
        ['curl', '-s', '-L', 'https://jobs.netflix.com'],
        capture_output=True, text=True, timeout=30, encoding='utf-8', errors='ignore'
    )
    html = r.stdout

    # Find all _next JS chunks
    js_files = re.findall(r'/_next/static/chunks/([^"\']+\.js)', html)
    js_files = list(set(js_files))

    print(f"  Found {len(js_files)} JS chunks")

    for js in js_files[:5]:
        js_url = f"https://jobs.netflix.com/_next/static/chunks/{js}"
        map_url = js_url + ".map"

        try:
            # Check if map exists
            mr = subprocess.run(
                ['curl', '-s', '-o', 'NUL', '-w', '%{http_code}', '-I', map_url],
                capture_output=True, text=True, timeout=10
            )
            code = mr.stdout.strip()
            if code == '200':
                print(f"    [FOUND!] {map_url}")
            elif code not in ['403', '404']:
                print(f"    [{code}] {js}")
        except:
            pass
except Exception as e:
    print(f"  Error: {e}")

# 4. Check Netflix CDN patterns
print("\n[4] Checking Netflix CDN for source maps...")
cdn_patterns = [
    "https://assets.nflxext.com/ffe/siteui/common/js/app.js.map",
    "https://codex.nflxext.com/static/bundle.js.map",
    "https://assets.nflxext.com/en_us/levers/bundle.js.map",
    "https://www.netflix.com/nf-components/nmhpFrameworkClient.js.map",
    "https://assets.nflxext.com/ffe/akira/bundle.js.map",
]

for cdn_url in cdn_patterns:
    try:
        cr = subprocess.run(
            ['curl', '-s', '-o', 'NUL', '-w', '%{http_code}', '-I', '--max-time', '5', cdn_url],
            capture_output=True, text=True, timeout=10
        )
        code = cr.stdout.strip()
        if code == '200':
            print(f"  [FOUND!] {cdn_url}")
        elif code not in ['403', '404', '000']:
            print(f"  [{code}] {cdn_url}")
    except:
        pass

# 5. Check gau URLs for .map files
print("\n[5] Checking historical URLs for .map files...")
gau_file = r"C:\Users\gokim\netflix-recon\gau_urls.txt"
if os.path.exists(gau_file):
    map_urls = []
    with open(gau_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if '.map' in line.lower() or 'sourcemap' in line.lower():
                map_urls.append(line.strip())

    print(f"  Found {len(map_urls)} potential map URLs in gau data")
    for url in map_urls[:20]:
        print(f"    - {url}")

# 6. Deep scan meechum.prod for more maps
print("\n[6] Deep scanning meechum.prod.netflix.net...")
try:
    r = subprocess.run(
        ['curl', '-s', '-L', '--max-time', '15', 'https://meechum.prod.netflix.net/'],
        capture_output=True, text=True, timeout=20, encoding='utf-8', errors='ignore'
    )
    html = r.stdout

    # Find all script sources
    scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', html, re.I)
    scripts += re.findall(r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', html)
    scripts = list(set(scripts))

    print(f"  Found {len(scripts)} scripts")

    for script in scripts:
        if script.startswith('/'):
            script_url = f"https://meechum.prod.netflix.net{script}"
        elif script.startswith('http'):
            script_url = script
        else:
            continue

        map_url = re.sub(r'\?.*$', '', script_url) + '.map'

        try:
            mr = subprocess.run(
                ['curl', '-s', '-o', 'NUL', '-w', '%{http_code}', '-I', '--max-time', '5', map_url],
                capture_output=True, text=True, timeout=10
            )
            code = mr.stdout.strip()
            if code == '200':
                print(f"    [FOUND!] {map_url}")
            elif code not in ['403', '404', '000']:
                print(f"    [{code}] {map_url}")
        except:
            pass
except Exception as e:
    print(f"  Error: {e}")

# 7. Check third-party services
print("\n[7] Checking third-party integrations...")
third_party = [
    "https://cdn.cookielaw.org/scripttemplates/otSDKStub.js.map",
    "https://www.googletagmanager.com/gtm.js.map",
    "https://www.google-analytics.com/analytics.js.map",
]

for tp in third_party:
    try:
        tr = subprocess.run(
            ['curl', '-s', '-o', 'NUL', '-w', '%{http_code}', '-I', '--max-time', '5', tp],
            capture_output=True, text=True, timeout=10
        )
        code = tr.stdout.strip()
        if code == '200':
            print(f"  [FOUND] {tp}")
    except:
        pass

print("\n" + "=" * 70)
print("Scan complete!")
