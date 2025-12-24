import subprocess
import re
import json
import os

print("=" * 70)
print("SMART SOURCE MAP HUNTER")
print("=" * 70)

# Strategy 1: Check sourceMappingURL in downloaded JS files
print("\n[STRATEGY 1] Checking sourceMappingURL in downloaded JS files...")
js_dir = r"C:\Users\gokim\netflix-recon\js-files"
for filename in os.listdir(js_dir):
    if filename.endswith('.js'):
        filepath = os.path.join(js_dir, filename)
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                # Find sourceMappingURL
                matches = re.findall(r'//[#@]\s*sourceMappingURL=([^\s]+)', content)
                if matches:
                    print(f"  [FOUND] {filename}: {matches}")
                # Find sourceURL
                sources = re.findall(r'//[#@]\s*sourceURL=([^\s]+)', content)
                if sources:
                    print(f"  [SOURCE] {filename}: {sources}")
        except Exception as e:
            pass

# Strategy 2: Check SourceMap HTTP header
print("\n[STRATEGY 2] Checking SourceMap HTTP headers...")
test_urls = [
    "https://www.netflix.com/",
    "https://jobs.netflix.com/",
    "https://help.netflix.com/",
    "https://about.netflix.com/",
    "https://media.netflix.com/",
    "https://devices.netflix.com/",
    "https://fast.com/",
    "https://top10.netflix.com/",
    "https://tudum.netflix.com/",
    "https://ir.netflix.net/",
]

for url in test_urls:
    try:
        result = subprocess.run(
            ['curl', '-s', '-I', '--max-time', '10', url],
            capture_output=True, text=True, timeout=15
        )
        headers = result.stdout.lower()
        if 'sourcemap' in headers or 'x-sourcemap' in headers:
            print(f"  [FOUND] {url}")
            print(f"    {[l for l in result.stdout.split('\\n') if 'source' in l.lower()]}")
    except:
        pass

# Strategy 3: Find webpack/vite build patterns
print("\n[STRATEGY 3] Analyzing webpack/vite patterns from alive hosts...")
patterns_to_check = [
    "/_next/static/chunks/webpack-",
    "/_next/static/chunks/main-",
    "/_next/static/chunks/pages/_app-",
    "/static/js/main.",
    "/static/js/bundle.",
    "/assets/js/app.",
    "/dist/bundle.",
    "/build/static/js/",
]

print("  Patterns identified for fuzzing:")
for p in patterns_to_check:
    print(f"    {p}*.js.map")

# Strategy 4: Extract JS URLs from interesting subdomains
print("\n[STRATEGY 4] Extracting JS from high-value subdomains...")
high_value = [
    "https://meechum.netflix.com/",
    "https://meechum.prod.netflix.net/",
    "https://partner.netflix.com/",
    "https://partners.netflix.com/",
    "https://openconnect.netflix.com/",
    "https://developer.netflix.com/",
    "https://research.netflix.com/",
]

for url in high_value:
    try:
        result = subprocess.run(
            ['curl', '-s', '-L', '--max-time', '10', url],
            capture_output=True, text=True, timeout=15, encoding='utf-8', errors='ignore'
        )
        html = result.stdout
        js_files = re.findall(r'["\']([^"\']*\.js)["\']', html)
        if js_files:
            print(f"\n  {url}")
            for js in list(set(js_files))[:5]:
                print(f"    - {js}")
    except Exception as e:
        pass

print("\n" + "=" * 70)
