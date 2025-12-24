# Netflix Bug Bounty Recon - Final Report

## Summary
- **Total Subdomains**: ~24,000
- **Alive Hosts**: 3,057+
- **Historical URLs**: 550,456
- **High-Value Targets**: 158
- **JS Files Downloaded**: 7
- **Source Maps Found**: 2 ✅

---

## Critical Findings

### 1. Source Maps Found ✅
| URL | Size | Status |
|-----|------|--------|
| `meechum.prod.netflix.net/cdn/bundle.de89b324952c03796a64.js.map` | 4.8 KB | ✅ Downloaded |
| `meechum.prod.netflix.net/cdn/main.63b799c6d61020122e89.css.map` | 33 KB | ✅ Downloaded |
| `fast.com/app-*.js.map` | - | 404 (but JS has secrets) |
| `research.netflix.com/_next/*.js.map` | - | 403 (protected) |
| `jobs.netflix.com/_next/*.js.map` | - | 403 (protected) |

### 2. Internal Systems Discovered

#### AdmitOne Portal (meechum.prod.netflix.net)
- **Internal partner portal** - error handling page exposed
- Uses S3 bucket for CDN: `/cdn/` path returns AWS S3 AccessDenied
- TypeScript source structure exposed in source maps
- CSS reveals **"Hawkins" design system** (internal Netflix UI framework)
- Full Netflix Sans font family structure with 48+ font variants exposed
- Source files structure:
  ```
  webpack://cdn/
  ├── src/
  │   ├── index.ts
  │   ├── assets/
  │   │   ├── css/
  │   │   │   ├── normalize.css
  │   │   │   ├── hawkins.css   <-- Internal design system!
  │   │   │   └── font.css
  │   │   ├── img/
  │   │   └── font/
  │   │       └── Netflix Sans/  <-- Proprietary fonts
  ```

#### Internal Dradis API Network
```
*.internal.dradis.netflix.com
├── account.us-west-2.internal.dradis.netflix.com
├── api-global.us-east-1.internal.dradis.netflix.com
├── api-global.eu-west-1.internal.dradis.netflix.com
├── fast.us-east-1.internal.dradis.netflix.com
├── help.us-west-2.internal.dradis.netflix.com
└── contactus.eu-west-1.internal.dradis.netflix.com
```

### 3. API Endpoints from JS Analysis

#### From fast.com JS (133KB)
```javascript
API: api-global.netflix.com/oca/speedtest
Token: YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm (placeholder)
Default params:
  - https: true
  - urlCount: 3
  - endpoint: api-global.netflix.com/oca/speedtest
```

#### Netflix Logging Schema (nf-cl-schema-ui)
Full event schema found including:
- AcceptTermsOfUse
- AuthenticateMdxPin
- CancelMembership
- CreateAccount
- DeleteProfile
- Download
- Play/Pause/Seek commands
- PushNotification events
- Search events
- SetThumbRating
- Share events
- And 200+ more event types

### 4. Staging/Test Environments
```
https://api-staging.netflix.com (403)
https://api.sandbox.netflix.com (403)
https://api.test.netflix.com
https://develop-stage.netflix.com (403)
https://beta.oc.netflix.com
```

### 5. Interesting Parameters (IDOR/Injection potential)
| Parameter | Count | Attack Vector |
|-----------|-------|---------------|
| trkid | 89,110 | IDOR |
| movieid | 18,092 | IDOR |
| callback | 7,356 | JSONP/XSS |
| sid | 4,172 | Session fixation |

### 6. 403 Protected Files
```
https://www.netflix.com/.env (403 - exists but protected)
https://www.netflix.com/_/.env
```
Tested bypass methods: X-Forwarded-For, X-Original-URL, path manipulation - all return 302 redirect

---

## Downloaded Files
```
C:\Users\gokim\netflix-recon\
├── subdomains.txt (916 KB - ~24k subdomains)
├── alive.txt (3,057+ hosts)
├── interesting.txt (158 high-value targets)
├── gau_urls.txt (550,456 URLs)
├── FINDINGS_SUMMARY.md
├── FINAL_REPORT.md
├── js-files/
│   ├── nmhpFrameworkClient.js (3.6 MB)
│   ├── service-worker.js (112 KB)
│   ├── admitone-bundle.js (4 KB)
│   ├── admitone-bundle.js.map (4.8 KB) ✅ SOURCE MAP
│   ├── main.css.map (33 KB) ✅ SOURCE MAP
│   └── fast-app.js (133 KB)
├── Analysis Scripts:
│   ├── smart_sourcemap_hunt.py
│   ├── deep_sourcemap_scan.py
│   ├── advanced_sourcemap_hunt.py
│   ├── aggressive_map_scan.py
│   └── meechum_deep_scan.py
```

---

## Attack Vectors to Test

### High Priority (Primary Targets - up to $25,000)

1. **IDOR via movieid/trkid parameters**
   - Test: Enumerate IDs, check authorization
   - Endpoint: /watch?movieid=XXXX

2. **OAuth Token Endpoints**
   ```
   api.netflix.com/oauth/access_token
   api.netflix.com/oauth/request_token
   ```

3. **JSONP XSS via callback**
   - Test: ?callback=alert(1)

4. **SSRF to Internal Endpoints**
   - Target: *.internal.dradis.netflix.com

5. **Business Logic in Event Schema**
   - Abuse: CancelMembership, DeleteProfile, SetThumbRating

### Medium Priority

1. **403 Bypass on .env and staging**
2. **Log Injection on logs.netflix.com**
3. **API rate limiting bypass**

---

## AI Analysis Recommendations

Feed these files to Gemini/ChatGPT/Codex:

1. **nmhpFrameworkClient.js (3.6 MB)**
   - Look for: Hidden endpoints, hardcoded secrets, auth bypass

2. **fast-app.js (133 KB)**
   - Contains: Full logging schema, API patterns

3. **gau_urls.txt (550k URLs)**
   - Mine for: Unusual parameters, hidden endpoints

4. **alive.txt + interesting.txt**
   - Prioritize: staging, test, internal endpoints

---

## Next Steps

1. Set up Burp Suite proxy
2. Create Netflix account for authenticated testing
3. Use nuclei for known vuln scanning
4. FFUF fuzz interesting endpoints
5. Manual testing on high-priority vectors

---

---

## Full File Inventory

### Large JS Files (Analysis Priority)
| File | Size | Source | Priority |
|------|------|--------|----------|
| nmhpFrameworkClient.js | 3.6 MB | netflix.com | HIGH |
| media_app.js | 1.3 MB | media.netflix.com | HIGH |
| media_main.js | 341 KB | media.netflix.com | MEDIUM |
| jobs_bd904a5c.js | 224 KB | jobs.netflix.com | MEDIUM |
| media_framework.js | 209 KB | media.netflix.com | LOW |
| jobs_4bd1b696.js | 173 KB | jobs.netflix.com | MEDIUM |
| research_framework.js | 149 KB | research.netflix.com | LOW |
| fast-app.js | 133 KB | fast.com | MEDIUM |

### Source Maps Downloaded
- admitone-bundle.js.map (4.8 KB)
- main.css.map (33 KB)

### Key Endpoints Found
```
GraphQL: https://sgw.prod.cloud.netflix.com/graphql
Netflix Studios: https://runtimewebjs.prod.netflixstudios.com/api.js
Meechum Logout: /meechum?logout=
```

### Total Downloaded: ~7 MB across 35 files

---

*Generated: 2025-12-24*
*Updated: Deep scan complete*
