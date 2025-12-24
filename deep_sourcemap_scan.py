import subprocess
import re
import concurrent.futures

print("=" * 70)
print("DEEP SOURCE MAP SCANNER")
print("=" * 70)

# Read interesting hosts
with open(r'C:\Users\gokim\netflix-recon\interesting.txt', 'r', encoding='utf-8', errors='ignore') as f:
    hosts = [h.strip() for h in f.readlines() if h.strip()]

print(f"\nScanning {len(hosts)} high-value hosts for JS files with source maps...")

def scan_host(url):
    results = []
    try:
        # Fetch the page
        r = subprocess.run(
            ['curl', '-s', '-L', '--max-time', '10', url],
            capture_output=True, text=True, timeout=15, encoding='utf-8', errors='ignore'
        )
        html = r.stdout

        # Find all JS files
        js_files = re.findall(r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', html)
        js_files = list(set(js_files))

        for js in js_files[:3]:  # Check first 3 JS per host
            # Build full URL
            if js.startswith('http'):
                js_url = js
            elif js.startswith('//'):
                js_url = 'https:' + js
            elif js.startswith('/'):
                base = url.rstrip('/')
                js_url = base + js
            else:
                continue

            # Fetch JS and check for sourceMappingURL
            try:
                jr = subprocess.run(
                    ['curl', '-s', '--max-time', '5', js_url],
                    capture_output=True, text=True, timeout=10, encoding='utf-8', errors='ignore'
                )
                js_content = jr.stdout

                # Check for sourceMappingURL
                map_match = re.search(r'//[#@]\s*sourceMappingURL=([^\s]+)', js_content)
                if map_match:
                    map_ref = map_match.group(1)

                    # Build map URL
                    if map_ref.startswith('http'):
                        map_url = map_ref
                    elif map_ref.startswith('data:'):
                        results.append((url, js_url, "INLINE_BASE64"))
                        continue
                    else:
                        # Relative path
                        js_base = '/'.join(js_url.split('/')[:-1])
                        map_url = js_base + '/' + map_ref

                    # Check if map exists
                    mr = subprocess.run(
                        ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '-I', '--max-time', '5', map_url],
                        capture_output=True, text=True, timeout=10
                    )
                    code = mr.stdout.strip()
                    if code == '200':
                        results.append((url, map_url, "FOUND_200"))
                    elif code not in ['403', '404', '000']:
                        results.append((url, map_url, f"STATUS_{code}"))
            except:
                pass
    except Exception as e:
        pass

    return results

# Scan hosts
all_results = []
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    futures = {executor.submit(scan_host, host): host for host in hosts[:50]}  # First 50
    for i, future in enumerate(concurrent.futures.as_completed(futures)):
        if (i+1) % 10 == 0:
            print(f"  Progress: {i+1}/50")
        try:
            results = future.result(timeout=30)
            if results:
                all_results.extend(results)
                for r in results:
                    print(f"  [!] {r[2]}: {r[1]}")
        except:
            pass

print(f"\n{'='*70}")
print(f"RESULTS: Found {len(all_results)} source map references")
for host, url, status in all_results:
    print(f"  [{status}] {url}")
