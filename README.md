# Netflix Jobs Security Research

## Target Scope
- **Primary**: jobs.netflix.com (Next.js App Router)
- **Secondary**: explore.jobs.netflix.net (Eightfold AI ATS)
- **Related**: jobs.netflixhouse.com, netflix.eightfold.ai

## Directory Structure

```
netflix/
├── js/                      # Main JS chunks from jobs.netflix.com (41 files)
├── css/                     # CSS files (4 files)
├── sdk/                     # Third-party SDKs (OneTrust, FB, GA)
├── eightfold_js/            # Eightfold platform JS (7 files)
├── eightfold_scripts/       # eval()'d scripts - CRITICAL for analysis
├── netflixhouse_js/         # Netflix House JS chunks (9 files)
├── wayback_js/              # Historical JS from Wayback Machine
├── source_maps/             # Third-party source maps (Bootstrap, jQuery)
├── api_responses/           # API response samples
├── FINDINGS.md              # Detailed findings report
├── ATTACK_VECTORS.md        # Attack chain documentation
└── README.md                # This file
```

## Critical Files for Analysis

### 1. eval() Supply Chain (HIGH PRIORITY)
**Location**: `eightfold_scripts/`
```
- bold_safari_fix.js      # eval()'d from static.vscdn.net
- inject_images.js        # eval()'d from static.vscdn.net
- pill_select_fix.js      # eval()'d from static.vscdn.net
```
These scripts are fetched and executed via `eval()` at runtime. Supply chain risk.

### 2. Main Application JS
**Location**: `js/`
```
- webpack-709c479c11f21dd0.js    # Webpack runtime
- main-app-e3f34a824956f8af.js   # Main app bundle
- layout-1e12dfbc464a357d.js     # Layout components
- 8663-f99d094955d8a02c.js       # Large chunk with React components
```

### 3. Eightfold Platform
**Location**: `eightfold_js/`
```
- base.37641cd3.js              # Main Eightfold app (470KB)
- jquery_v3.4df69f02.js         # jQuery with innerHTML sinks
- bootstrap_v5.5ca2d4ac.js      # Bootstrap JS
- i18n_override.js              # Netflix customizations
```

## Known Vulnerabilities

### Confirmed
1. **Information Disclosure** - localhost:7001 URL in production meta tags
2. **eval() Pattern** - Remote code fetched and eval()'d
3. **Build ID Exposure** - TdjX6KQ9aufhEgFkzm7aP

### Potential (Need PoC)
1. **XSS via dangerouslySetInnerHTML** - 30+ sinks found
2. **postMessage DOM XSS** - Message handlers with Function()
3. **Contentful CMS Injection** - Space ID: i5wc420v2vd1

## Analysis Tasks for AI

### Task 1: Trace Data Flow
Find source → sink chains for XSS:
```javascript
// Look for patterns like:
dangerouslySetInnerHTML={{__html: userInput}}
element.innerHTML = data.fromAPI
```

### Task 2: postMessage Handler Analysis
Find message handlers without origin validation:
```javascript
// Look for:
window.addEventListener('message', function(e) {
  // No e.origin check
  eval(e.data) or Function(e.data)()
})
```

### Task 3: API Injection Points
Check if API responses are sanitized before rendering:
- `/api/search?q=` - Search functionality
- RSC flight data in `__next_f` arrays
- Contentful CMS data

### Task 4: Supply Chain Analysis
Analyze eval()'d scripts for:
- DOM manipulation without sanitization
- User input handling
- Potential for injecting malicious code

## Technology Stack

| Component | Technology |
|-----------|------------|
| Frontend | Next.js 14+ (App Router, RSC) |
| CMS | Contentful |
| ATS | Eightfold AI |
| CDN | Vercel Edge, CloudFront |
| Analytics | GA4, Facebook Pixel |
| Consent | OneTrust |

## API Endpoints Discovered

```
jobs.netflix.com:
- /api/search
- /__nextjs_original-stack-frame

explore.jobs.netflix.net:
- /api/apply/v2/jobs
- /api/application/v2/bootstrap_application
- /api/application/v2/profile
```

## WAF Notes
- Netflix WAF blocks: .map, .env, package.json
- All source map bypass attempts failed
- S3/CloudFront additional blocking on Eightfold CDN

## Files to Prioritize

1. `eightfold_scripts/*.js` - Unminified, eval()'d code
2. `js/8663-*.js` - Large chunk with React components
3. `js/main-app-*.js` - Main application logic
4. `eightfold_js/base.*.js` - Eightfold main bundle
5. `FINDINGS.md` - Detailed vulnerability report
