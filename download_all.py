import subprocess
import os
import re

output_dir = r"C:\Users\gokim\netflix-recon\js-files"

print("=" * 70)
print("DOWNLOADING ALL NETFLIX JS FILES")
print("=" * 70)

downloads = []

# 1. Research.netflix.com JS files
print("\n[1] Downloading research.netflix.com JS files...")
research_js = [
    "https://research.netflix.com/_next/static/7927b847d9436d85908f311566e13402df8606c0/pages/index.js",
    "https://research.netflix.com/_next/static/7927b847d9436d85908f311566e13402df8606c0/pages/_app.js",
    "https://research.netflix.com/_next/static/runtime/webpack-b65cab0b00afd201cbda.js",
    "https://research.netflix.com/_next/static/chunks/framework.b7d936a06c1d98f380d6.js",
    "https://research.netflix.com/_next/static/chunks/commons.da91b7b7bc814507a614.js",
    "https://research.netflix.com/_next/static/runtime/main-0487dea18ec5e93c6c88.js",
]

for url in research_js:
    filename = "research_" + url.split("/")[-1]
    filepath = os.path.join(output_dir, filename)
    try:
        r = subprocess.run(
            ['curl', '-s', '-o', filepath, url],
            capture_output=True, timeout=30
        )
        size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
        if size > 100:
            print(f"  [OK] {filename} ({size:,} bytes)")
            downloads.append((filename, size))
        else:
            print(f"  [FAIL] {filename}")
    except Exception as e:
        print(f"  [ERROR] {filename}: {e}")

# 2. Jobs.netflix.com
print("\n[2] Fetching jobs.netflix.com JS files...")
try:
    r = subprocess.run(
        ['curl', '-s', '-A', 'Mozilla/5.0', 'https://jobs.netflix.com/'],
        capture_output=True, text=True, timeout=30, encoding='utf-8', errors='ignore'
    )
    js_files = re.findall(r'/_next/static/[^"\']+\.js', r.stdout)
    js_files = list(set(js_files))[:10]

    for js in js_files:
        url = "https://jobs.netflix.com" + js
        filename = "jobs_" + js.split("/")[-1]
        filepath = os.path.join(output_dir, filename)
        try:
            subprocess.run(['curl', '-s', '-o', filepath, url], timeout=30)
            size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
            if size > 100:
                print(f"  [OK] {filename} ({size:,} bytes)")
                downloads.append((filename, size))
        except:
            pass
except Exception as e:
    print(f"  Error: {e}")

# 3. Fast.com main app
print("\n[3] Downloading fast.com files...")
fast_files = [
    ("https://fast.com/app.js", "fast_app_main.js"),
    ("https://fast.com/app.css", "fast_app.css"),
]
for url, filename in fast_files:
    filepath = os.path.join(output_dir, filename)
    try:
        subprocess.run(['curl', '-s', '-o', filepath, url], timeout=30)
        size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
        if size > 100:
            print(f"  [OK] {filename} ({size:,} bytes)")
            downloads.append((filename, size))
    except:
        pass

# 4. Netflix CDN assets
print("\n[4] Checking Netflix CDN (nflxext.com)...")
cdn_patterns = [
    "https://assets.nflxext.com/ffe/siteui/common/js/app.js",
    "https://assets.nflxext.com/ffe/siteui/akira/js/app.js",
    "https://assets.nflxext.com/en_us/levers/bundle.js",
]
for url in cdn_patterns:
    filename = "cdn_" + url.split("/")[-1]
    filepath = os.path.join(output_dir, filename)
    try:
        r = subprocess.run(
            ['curl', '-s', '-o', filepath, '-w', '%{http_code}', url],
            capture_output=True, text=True, timeout=30
        )
        if r.stdout.strip() == '200':
            size = os.path.getsize(filepath)
            print(f"  [OK] {filename} ({size:,} bytes)")
            downloads.append((filename, size))
    except:
        pass

# 5. OpenConnect (partner portal)
print("\n[5] Checking openconnect.netflix.com...")
try:
    r = subprocess.run(
        ['curl', '-s', '-A', 'Mozilla/5.0', '-L', 'https://openconnect.netflix.com/'],
        capture_output=True, text=True, timeout=30, encoding='utf-8', errors='ignore'
    )
    js_files = re.findall(r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', r.stdout)
    js_files = [j for j in js_files if not j.startswith('http') or 'netflix' in j][:5]

    for js in js_files:
        if js.startswith('/'):
            url = "https://openconnect.netflix.com" + js
        elif js.startswith('http'):
            url = js
        else:
            continue
        filename = "openconnect_" + js.split("/")[-1].split("?")[0]
        filepath = os.path.join(output_dir, filename)
        try:
            subprocess.run(['curl', '-s', '-o', filepath, url], timeout=30)
            size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
            if size > 100:
                print(f"  [OK] {filename} ({size:,} bytes)")
                downloads.append((filename, size))
        except:
            pass
except Exception as e:
    print(f"  Error: {e}")

# 6. Top10.netflix.com
print("\n[6] Checking top10.netflix.com...")
try:
    r = subprocess.run(
        ['curl', '-s', '-A', 'Mozilla/5.0', '-L', 'https://top10.netflix.com/'],
        capture_output=True, text=True, timeout=30, encoding='utf-8', errors='ignore'
    )
    js_files = re.findall(r'/_next/static/[^"\']+\.js', r.stdout)
    js_files = list(set(js_files))[:5]

    for js in js_files:
        url = "https://top10.netflix.com" + js
        filename = "top10_" + js.split("/")[-1]
        filepath = os.path.join(output_dir, filename)
        try:
            subprocess.run(['curl', '-s', '-o', filepath, url], timeout=30)
            size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
            if size > 100:
                print(f"  [OK] {filename} ({size:,} bytes)")
                downloads.append((filename, size))
        except:
            pass
except Exception as e:
    print(f"  Error: {e}")

# Summary
print("\n" + "=" * 70)
print(f"DOWNLOAD COMPLETE: {len(downloads)} files")
print("=" * 70)
total_size = sum(d[1] for d in downloads)
print(f"Total new size: {total_size:,} bytes ({total_size/1024/1024:.2f} MB)")

for name, size in sorted(downloads, key=lambda x: -x[1])[:15]:
    print(f"  {name}: {size:,} bytes")
