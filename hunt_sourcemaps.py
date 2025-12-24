import subprocess
import concurrent.futures
import re

# Read JS URLs from gau
with open(r'C:\Users\gokim\netflix-recon\gau_urls.txt', 'r', encoding='utf-8', errors='ignore') as f:
    urls = f.readlines()

# Filter only .js URLs
js_urls = [u.strip() for u in urls if u.strip().endswith('.js')]
print(f"Found {len(js_urls)} JS files to check for source maps")

# Test each JS URL for .map
def check_sourcemap(js_url):
    map_url = js_url + '.map'
    try:
        result = subprocess.run(
            ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '-I', '--max-time', '5', map_url],
            capture_output=True, text=True, timeout=10
        )
        code = result.stdout.strip()
        if code in ['200', '301', '302']:
            return (map_url, code)
    except:
        pass
    return None

print("\nChecking for source maps...")
found_maps = []

# Check first 200 JS files
for i, js_url in enumerate(js_urls[:200]):
    if i % 20 == 0:
        print(f"Progress: {i}/200")
    result = check_sourcemap(js_url)
    if result:
        found_maps.append(result)
        print(f"[FOUND] {result[0]} - {result[1]}")

print(f"\n=== RESULTS ===")
print(f"Total source maps found: {len(found_maps)}")
for url, code in found_maps:
    print(f"  {code}: {url}")
