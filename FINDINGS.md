# Netflix Jobs Recon - Findings Report

## Downloaded Assets Summary
```
jobs.netflix.com JS:        41 files
jobs.netflix.com CSS:        4 files
SDK files (OneTrust/GA/FB):  3 files
netflixhouse JS:             9 files
Eightfold JS:                7 files (incl. i18n_override)
Eightfold eval scripts:      3 files
Wayback archived JS:         3 files (2017-2018)
Source maps (3rd party):     2 files (Bootstrap, jQuery)
HTML pages:                  4 files
TOTAL SIZE:              ~4.5 MB
```

## Critical Findings

### 1. Information Disclosure - localhost URL Leak
**Severity: Low-Medium**
**Location**: jobs.netflix.com (via X-Original-URL header response)
```html
<meta property="og:url" content="http://localhost:7001">
```
- Development/staging configuration leaking in production
- OneTrust test domain: `22ee2df4-2249-4280-8b58-e53ceefcac95-test`

### 2. eval() Code Execution Pattern (Supply Chain Risk)
**Severity: Medium**
**Location**: explore.jobs.netflix.net (Eightfold platform)
```javascript
fetch('https://static.vscdn.net/images/careers/demo/netflix/...')
  .then(response => response.text())
  .then(code => eval(code))
```
**URLs being eval'd:**
- `static.vscdn.net/images/careers/demo/netflix/1746474152::bold_safari_fix_cutover1`
- `static.vscdn.net/images/careers/demo/netflix/1746474521::inject_images_main_cutover1.1`
- `static.vscdn.net/images/careers/demo/netflix/1746474217::pill_select_fix_cutover1`

**Risk**: If vscdn.net is compromised or admin credentials leaked, arbitrary JS execution

### 3. Exposed Build IDs
- jobs.netflix.com: `TdjX6KQ9aufhEgFkzm7aP`
- jobs.netflixhouse.com: `-ilrw9PfshKJplwo__hrS`

### 4. Contentful CMS Exposure
- Space ID: `i5wc420v2vd1`
- All images: `images.ctfassets.net/i5wc420v2vd1/`
- API requires authentication (401)

### 5. Third-Party Service IDs
```
OneTrust Domain Scripts:
- jobs.netflix.com: 22ee2df4-2249-4280-8b58-e53ceefcac95
- netflixhouse.com: 0196b453-6267-7b85-b7f7-fc32f6900f57

Google Analytics:
- G-4Y3WKF2MY1 (jobs.netflix)
- G-C096SPJ72K (netflixhouse)
- G-8XHF9J4KQ8 (explore.jobs)

reCAPTCHA:
- 6LfwboYUAAAAAJb6QcVuRXi7R9pTqgGKF6TnNzia

Facebook Pixel:
- Active on all sites
```

### 6. XSS Sinks Found
- 30+ dangerouslySetInnerHTML usages
- Dynamic patterns: `__html: e`, `__html: t`
- postMessage handlers with MessageChannel

### 7. SSG Routes Discovered
```javascript
self.__SSG_MANIFEST = new Set([
  "/[slug]",
  "/careers/[slug]",
  "/locations/[slug]"
]);
```

### 8. Eightfold Platform Information Disclosure
**Severity: Low**
**Location**: explore.jobs.netflix.net
```
CSRF Token Pattern: IjkwMWMyNjRiY2MwMzAxODVjZTEyYjAwMjQ3NjM1MTczY2Y0OTVkYWEi.HCznug.xxx
Trace ID Pattern: 73437bf1766e4fc49b31734f1546c3e5
User: loggedout@none.com
Group: Unknown
```
- Chrome extension ID: ljdhjggpgnkjlfpbkodmafnomalmomnc
- Netflix branding theme colors exposed in code element

### 9. Next.js Stack Frame API Accessible
**Severity: Low**
**Location**: jobs.netflix.com/__nextjs_original-stack-frame
- Endpoint responds with RSC flight data
- Reveals complete navigation structure
- All office locations with image URLs exposed
- This endpoint should ideally be disabled in production

### 10. Historical Assets from Wayback Machine
**Location**: web.archive.org
- 2017-2019 Next.js builds available
- Old build hashes: 716b91033e36a1844881ce483737e54aac3179e1
- Some older JS files are less minified
- Potential for finding hardcoded secrets in historical builds

### 11. Netflix i18n Override Exposure
**Severity: Informational**
**Location**: static.vscdn.net/gen/i18n/i18n_override_netflix.com_en_*.js
- Internal terminology mappings exposed
- "Mentor" → "Colleague Connections"
- "Ideal Candidate" → "Example Candidate"
- Internal UI customization patterns visible

## Source Map Hunting Results
```
✗ jobs.netflix.com/_next/static/*.map - 403 Forbidden (WAF)
✗ netflix.eightfold.ai/gen/*.map - 403 Forbidden (S3)
✗ static.vscdn.net/*.map - 403 Forbidden (CloudFront)
✓ Bootstrap source map from jsDelivr (3rd party)
✓ jQuery source map from jsDelivr (3rd party)
```
All Netflix-hosted source maps are blocked by WAF.

## Eightfold API Endpoints Discovered
```
/api/application/v2/bootstrap_application
/api/application/v2/profile
/api/ (returns 404 page with debug info)
```

## Related Subdomains
- explore.jobs.netflix.net (Eightfold AI ATS)
- jobs.netflixhouse.com (Next.js)
- apply.netflixhouse.com (Job applications)
- netflix.eightfold.ai (ATS backend)
- static.vscdn.net (Eightfold CDN)
- assets.nflxext.com (Netflix assets - returns 200)

## WAF Notes
- Netflix WAF blocks: .map, .env, package.json, robots.txt
- Source maps return 403
- All bypass attempts failed:
  - URL encoding variations
  - X-Original-URL header
  - Case manipulation
  - HTTP method changes
  - Vercel protection bypass header
- X-Original-URL header reveals localhost:7001 configuration

## Next Steps for Testing
1. Test postMessage handlers for XSS
2. Analyze dangerouslySetInnerHTML data flow
3. Check Contentful API for misconfigurations
4. Test RSC flight data injection
5. Enumerate Eightfold admin endpoints
6. Test CSRF token predictability
7. Analyze Bootstrap source map for version vulnerabilities
8. Check Wayback Machine for more historical secrets
