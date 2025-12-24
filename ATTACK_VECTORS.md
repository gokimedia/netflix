# Netflix Jobs - Attack Vectors for Bug Bounty

## Priority Attack Chains

### 1. eval() Supply Chain Attack (HIGH PRIORITY)
**Severity: Medium-High**
**Location**: explore.jobs.netflix.net via Eightfold branding config

```javascript
// From bootstrap_application API response:
fetch('https://static.vscdn.net/images/careers/demo/netflix/1746474152::bold_safari_fix_cutover1')
  .then(response => response.text())
  .then(code => eval(code))
```

**Attack Scenario**:
- If attacker gains access to Netflix's Eightfold admin panel
- Or if vscdn.net CDN is compromised
- Arbitrary JavaScript execution on all visitors

**Files to analyze**:
- `eightfold_scripts/bold_safari_fix.js`
- `eightfold_scripts/inject_images.js`
- `eightfold_scripts/pill_select_fix.js`

**PoC needed**: Show the full attack chain from CDN to victim browser

---

### 2. Contentful CMS XSS (MEDIUM PRIORITY)
**Severity: Medium**
**Location**: jobs.netflix.com RSC data

**Observed Data Flow**:
```
Contentful API → RSC Flight Data → dangerouslySetInnerHTML
                     ↓
             images.ctfassets.net/i5wc420v2vd1/
```

**Attack Scenario**:
- If Contentful space has misconfigured permissions
- Or admin account is compromised
- XSS via CMS content injection

**What we need**:
1. Test Contentful API access: `https://cdn.contentful.com/spaces/i5wc420v2vd1/...`
2. Find which fields flow to innerHTML sinks
3. Trace RSC data deserialization

---

### 3. postMessage DOM XSS (MEDIUM PRIORITY)
**Severity: Medium**
**Location**: Main JS chunks

**Found Pattern**:
```javascript
Function(""+n)()  // In postMessage handler
```

**What we need**:
1. Identify message origin validation
2. Find injectable message data
3. Create PoC with iframe

---

### 4. URL Parameter Reflection
**Status**: TESTED - NOT VULNERABLE
```
/search?q=<script>alert(1)</script> → NOT reflected
```
Netflix properly sanitizes URL parameters.

---

## Files We Have vs What We Need

### HAVE (Downloaded):
```
✓ 41 JS chunks (minified)
✓ Eightfold eval scripts (unminified!)
✓ API responses (bootstrap, jobs)
✓ RSC flight data samples
✓ i18n override config
```

### NEED for Complete PoC:
```
[ ] Contentful API token or public access test
[ ] postMessage handler source identification
[ ] dangerouslySetInnerHTML exact data sources
[ ] iframe origin validation bypass
```

---

## Recommended Next Steps

1. **Test Contentful API** - Check if space is publicly readable
2. **Trace innerHTML sinks** - Map exact data flow in minified JS
3. **postMessage PoC** - Create iframe to test message handling
4. **Eightfold admin enum** - Check for auth bypass on admin endpoints

---

## Quick Win Opportunities

### Information Disclosure (Already Found):
- localhost:7001 in meta tags (Low)
- Build IDs exposed (Informational)
- Contentful Space ID (Informational)
- OneTrust test domain (Low)

### Potential Higher Severity:
- eval() pattern → Supply chain risk (Medium+)
- postMessage + Function() → Potential DOM XSS (Medium+)
- Contentful → CMS XSS if misconfigured (Medium+)
