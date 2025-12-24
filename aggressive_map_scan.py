import subprocess
import re
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

print("=" * 70)
print("AGGRESSIVE SOURCE MAP SCANNER")
print("=" * 70)

# Load interesting hosts
with open(r'C:\Users\gokim\netflix-recon\interesting.txt', 'r', encoding='utf-8', errors='ignore') as f:
    hosts = [h.strip() for h in f.readlines() if h.strip()]

print(f"\nLoaded {len(hosts)} high-value hosts")

def fetch_and_analyze(url):
    """Fetch a URL, find JS files, and check for source maps"""
    findings = []
    try:
        r = subprocess.run(
            ['curl', '-s', '-L', '--max-time', '10', '-A', 'Mozilla/5.0', url],
            capture_output=True, text=True, timeout=15, encoding='utf-8', errors='ignore'
        )
        html = r.stdout

        if not html or len(html) < 100:
            return findings

        # Extract all JS references
        js_patterns = [
            r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']',
            r'["\']([^"\']*/_next/[^"\']*\.js)["\']',
            r'["\']([^"\']*bundle[^"\']*\.js)["\']',
            r'["\']([^"\']*chunk[^"\']*\.js)["\']',
            r'["\']([^"\']*webpack[^"\']*\.js)["\']',
            r'["\']([^"\']*main[^"\']*\.js)["\']',
            r'["\']([^"\']*app[^"\']*\.js)["\']',
        ]

        js_files = set()
        for pattern in js_patterns:
            matches = re.findall(pattern, html, re.I)
            js_files.update(matches)

        # Parse base URL
        from urllib.parse import urljoin, urlparse
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Check each JS file
        for js in list(js_files)[:5]:  # Limit to 5 per host
            # Build full URL
            if js.startswith('http'):
                js_url = js
            elif js.startswith('//'):
                js_url = 'https:' + js
            elif js.startswith('/'):
                js_url = base_url + js
            else:
                js_url = urljoin(url, js)

            # Clean query params for map URL
            clean_js = re.sub(r'\?.*$', '', js_url)
            map_url = clean_js + '.map'

            try:
                mr = subprocess.run(
                    ['curl', '-s', '-o', 'NUL', '-w', '%{http_code}', '-I', '--max-time', '5', '-A', 'Mozilla/5.0', map_url],
                    capture_output=True, text=True, timeout=10
                )
                code = mr.stdout.strip()

                if code == '200':
                    findings.append(('MAP_FOUND', url, map_url))
                elif code in ['301', '302', '307', '308']:
                    findings.append(('REDIRECT', url, map_url))

                # Also try SourceMap header on JS file
                hr = subprocess.run(
                    ['curl', '-s', '-I', '--max-time', '5', '-A', 'Mozilla/5.0', js_url],
                    capture_output=True, text=True, timeout=10
                )
                if 'sourcemap' in hr.stdout.lower() or 'x-sourcemap' in hr.stdout.lower():
                    findings.append(('HEADER_MAP', url, js_url))

            except:
                pass

            # Check for inline source map
            try:
                jr = subprocess.run(
                    ['curl', '-s', '--max-time', '5', '-A', 'Mozilla/5.0', js_url],
                    capture_output=True, text=True, timeout=10, encoding='utf-8', errors='ignore'
                )
                js_content = jr.stdout
                if 'sourceMappingURL=data:' in js_content:
                    findings.append(('INLINE_MAP', url, js_url))
                elif 'sourceMappingURL=' in js_content:
                    map_match = re.search(r'sourceMappingURL=([^\s]+)', js_content)
                    if map_match:
                        map_ref = map_match.group(1)
                        if not map_ref.startswith('data:'):
                            findings.append(('EXTERNAL_MAP_REF', url, f"{js_url} -> {map_ref}"))
            except:
                pass

    except Exception as e:
        pass

    return findings

# Scan all hosts
print("\nScanning hosts for source maps...")
all_findings = []

with ThreadPoolExecutor(max_workers=15) as executor:
    futures = {executor.submit(fetch_and_analyze, host): host for host in hosts}

    for i, future in enumerate(as_completed(futures)):
        if (i+1) % 20 == 0:
            print(f"  Progress: {i+1}/{len(hosts)}")
        try:
            results = future.result(timeout=60)
            if results:
                all_findings.extend(results)
                for finding in results:
                    print(f"  [!] {finding[0]}: {finding[2][:80]}...")
        except:
            pass

print(f"\n{'='*70}")
print(f"RESULTS: Found {len(all_findings)} source map references")
print("="*70)

# Group by type
map_types = {}
for finding in all_findings:
    ftype = finding[0]
    if ftype not in map_types:
        map_types[ftype] = []
    map_types[ftype].append(finding)

for ftype, findings in map_types.items():
    print(f"\n[{ftype}] - {len(findings)} findings:")
    for f in findings[:10]:
        print(f"  {f[2][:100]}")

# Save results
with open(r'C:\Users\gokim\netflix-recon\sourcemap_findings.txt', 'w') as f:
    for finding in all_findings:
        f.write(f"{finding[0]}|{finding[1]}|{finding[2]}\n")

print(f"\nResults saved to sourcemap_findings.txt")
