import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

print("=" * 70)
print("NEXT.JS SUBDOMAIN SCANNER")
print("=" * 70)

# Load alive hosts
with open(r'C:\Users\gokim\netflix-recon\alive.txt', 'r', encoding='utf-8', errors='ignore') as f:
    hosts = [h.strip() for h in f.readlines() if h.strip()]

print(f"Scanning {len(hosts)} hosts for Next.js...")

nextjs_hosts = []

def check_nextjs(url):
    try:
        r = subprocess.run(
            ['curl', '-s', '-L', '--max-time', '8', '-A', 'Mozilla/5.0', url],
            capture_output=True, text=True, timeout=12, encoding='utf-8', errors='ignore'
        )
        html = r.stdout

        # Next.js indicators
        indicators = []

        if '/_next/' in html:
            indicators.append('/_next/')
        if '__NEXT_DATA__' in html:
            indicators.append('__NEXT_DATA__')
        if 'next/head' in html.lower():
            indicators.append('next/head')
        if '_next/static' in html:
            indicators.append('_next/static')
        if 'buildId' in html and '_next' in html:
            indicators.append('buildId')

        if indicators:
            # Extract build ID if present
            build_match = re.search(r'/_next/static/([a-zA-Z0-9_-]{20,})/', html)
            build_id = build_match.group(1) if build_match else None

            # Count JS files
            js_count = len(re.findall(r'/_next/static/[^"\']+\.js', html))

            return (url, indicators, build_id, js_count)
    except:
        pass
    return None

# Scan with thread pool
with ThreadPoolExecutor(max_workers=20) as executor:
    futures = {executor.submit(check_nextjs, host): host for host in hosts}

    for i, future in enumerate(as_completed(futures)):
        if (i+1) % 100 == 0:
            print(f"  Progress: {i+1}/{len(hosts)}")
        try:
            result = future.result(timeout=15)
            if result:
                nextjs_hosts.append(result)
                print(f"  [NEXT.JS] {result[0]} - {result[1]}")
        except:
            pass

print("\n" + "=" * 70)
print(f"RESULTS: Found {len(nextjs_hosts)} Next.js sites")
print("=" * 70)

for url, indicators, build_id, js_count in sorted(nextjs_hosts, key=lambda x: -x[3]):
    print(f"\n{url}")
    print(f"  Indicators: {', '.join(indicators)}")
    if build_id:
        print(f"  Build ID: {build_id}")
    print(f"  JS Files: {js_count}")

# Save results
with open(r'C:\Users\gokim\netflix-recon\nextjs_hosts.txt', 'w') as f:
    for url, indicators, build_id, js_count in nextjs_hosts:
        f.write(f"{url}|{','.join(indicators)}|{build_id or 'N/A'}|{js_count}\n")

print(f"\nResults saved to nextjs_hosts.txt")
