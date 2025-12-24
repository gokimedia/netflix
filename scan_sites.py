import subprocess
import re
import json

sites = [
    "https://about.netflix.com/",
    "https://media.netflix.com/",
    "https://ir.netflix.net/",
    "https://jobs.netflix.com/",
    "https://research.netflix.com/",
    "https://openconnect.netflix.com/",
    "https://tudum.netflix.com/",
    "https://fast.com/",
    "https://top10.netflix.com/",
]

def fetch_and_extract(url):
    try:
        result = subprocess.run(
            ['powershell', '-Command', f"(Invoke-WebRequest -Uri '{url}' -UseBasicParsing -TimeoutSec 10).Content"],
            capture_output=True, text=True, timeout=20
        )
        html = result.stdout
        # Find JS files
        js_files = re.findall(r'["\']([^"\']*\.js)["\']', html)
        return url, list(set(js_files))
    except Exception as e:
        return url, []

print("Scanning Netflix sites for JS files...\n")

all_js = {}
for site in sites:
    print(f"Scanning: {site}")
    url, js_files = fetch_and_extract(site)
    if js_files:
        all_js[url] = js_files[:10]
        for js in js_files[:5]:
            print(f"  - {js}")

print("\n=== Checking for source maps ===")
for site, js_list in all_js.items():
    for js in js_list[:3]:
        if js.startswith('http'):
            map_url = js + '.map'
        elif js.startswith('/'):
            base = site.rstrip('/')
            map_url = base + js + '.map'
        else:
            continue

        try:
            result = subprocess.run(
                ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '-I', '--max-time', '5', map_url],
                capture_output=True, text=True, timeout=10
            )
            code = result.stdout.strip()
            if code == '200':
                print(f"[FOUND!] {map_url}")
            elif code not in ['403', '404', '000']:
                print(f"[{code}] {map_url}")
        except:
            pass
