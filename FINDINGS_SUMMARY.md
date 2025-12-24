# Netflix Bug Bounty Recon Summary

## Scope Info
- **Primary Targets**: $5,000 - $25,000 (Critical)
- **Focus Areas**: XSS, CSRF, SQLi, SSRF, Auth issues, Business Logic

## Recon Statistics
- **Subdomains Found**: ~24,000
- **Alive Hosts**: 3,057+
- **Historical URLs (gau)**: 550,456
- **Interesting Targets**: 158

---

## High-Value Targets Found

### Internal/Staging Endpoints
```
https://api-staging.netflix.com
https://api.sandbox.netflix.com
https://api.test.netflix.com
https://api-eu-staging.netflix.com
https://develop-stage.netflix.com
https://beta.oc.netflix.com
```

### Internal Dradis API (Multiple Regions)
```
*.internal.dradis.netflix.com
- account.us-west-2.internal.dradis.netflix.com
- api-global.us-east-1.internal.dradis.netflix.com
- api-global.eu-west-1.internal.dradis.netflix.com
- fast.us-east-1.internal.dradis.netflix.com
```

### Test/Dev Endpoints
```
https://ads.test.netflix.com
https://advertising.test.netflix.com
https://api.test.netflix.com
https://beacon.test.netflix.com
https://customerevents.test.netflix.com
https://ichnaea.test.netflix.com
```

---

## API Endpoints Discovered

### OAuth (Potential Auth Bypass)
```
http://api.netflix.com/oauth/access_token
http://api.netflix.com/oauth/request_token
```

### Catalog API
```
http://api.netflix.com/catalog/genres
http://api.netflix.com/catalog/titles/
http://api.netflix.com/catalog/people/
http://api.netflix.com/categories/
```

### Internal APIs
```
http://api-global.netflix.com/apps/nrdjs/upgrade_policy
http://api-public.netflix.com
http://jet-api.netflix.com
http://mbtest-api.netflix.com
```

---

## Interesting Parameters (Attack Vectors)

| Parameter | Count | Potential Attack |
|-----------|-------|------------------|
| trkid | 89110 | IDOR |
| movieid | 18092 | IDOR |
| callback | 7356 | JSONP/XSS |
| sid | 4172 | Session fixation |
| trackId | 3502 | IDOR |
| source | 2568 | Open redirect |
| locale | 2868 | LFI |

---

## Potential Vulnerabilities to Test

### 1. .env File Exposure
```
https://www.netflix.com/.env - Returns 403 (exists but protected)
https://www.netflix.com/_/.env - Test needed
```
**Test**: Try path traversal, different methods

### 2. IDOR on movieid/trkid Parameters
```
/watch?movieid=12345
/tracking?trkid=12345
```
**Test**: Enumerate IDs, check authorization

### 3. OAuth Token Endpoints
```
http://api.netflix.com/oauth/access_token
http://api.netflix.com/oauth/request_token
```
**Test**: Token leakage, weak validation

### 4. JSONP Callbacks
```
?callback=malicious_function
```
**Test**: XSS via callback parameter

### 5. Internal API Access
```
*.internal.dradis.netflix.com
```
**Test**: SSRF to internal endpoints, auth bypass

### 6. Logging Endpoints
```
android*.logs.netflix.com
ichnaea.netflix.com
beacon.netflix.com
```
**Test**: Log injection, data leakage

---

## Android Apps (for Mobile Testing)
```
com.netflix.mediaclient (Main app)
com.netflix.ninja
com.netflix.bheem
com.netflix.robin
com.netflix.NGP.Pandora
com.netflix.starfire
```

---

## JavaScript Files Downloaded
1. nmhpFrameworkClient.js (3.6 MB)
2. service-worker.js (112 KB)

---

## Next Steps for AI Analysis

1. **Feed JS files to AI** for:
   - Hidden API endpoints
   - Hardcoded tokens/secrets
   - Business logic flaws
   - Client-side validation bypass

2. **Test interesting endpoints** with:
   - Burp Suite
   - FFUF for fuzzing
   - Nuclei for known vulns

3. **Focus on**:
   - Primary targets (www.netflix.com, api*.netflix.com)
   - OAuth flows
   - IDOR parameters
   - Internal endpoint access
