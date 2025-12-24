import re

with open(r'C:\Users\gokim\netflix-recon\netflix_home.html', 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

# Find JS URLs
pattern = r'src=["\']([^"\']+\.js[^"\']*)["\']'
js_urls = re.findall(pattern, content)

# Also find nflximg/nflxso URLs
cdn_pattern = r'(https://[a-zA-Z0-9._/-]*nflx[a-zA-Z0-9._/-]+)'
cdn_urls = re.findall(cdn_pattern, content)

print("=== JavaScript Files ===")
for url in sorted(set(js_urls)):
    print(url)

print("\n=== CDN URLs ===")
for url in sorted(set(cdn_urls))[:20]:
    print(url)
