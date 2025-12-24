#!/usr/bin/env python3
"""
Shared security posture checks for HTTP responses.
"""

import re
from typing import Dict, List


def normalize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    if not headers:
        return {}
    return {str(k).lower(): str(v) for k, v in headers.items()}


def _add(findings: List[dict], severity: str, title: str, detail: str, evidence: Dict = None):
    item = {
        "severity": severity,
        "title": title,
        "detail": detail,
    }
    if evidence:
        item["evidence"] = evidence
    findings.append(item)


def _split_set_cookie(raw_value: str) -> List[str]:
    if not raw_value:
        return []
    return re.split(r", (?=[^;=]+=)", raw_value)


def evaluate_security_headers(headers: Dict[str, str], content_type: str = "") -> List[dict]:
    findings: List[dict] = []
    h = normalize_headers(headers)

    hsts = h.get("strict-transport-security", "")
    if not hsts:
        _add(findings, "MEDIUM", "Missing HSTS", "strict-transport-security header is missing")
    else:
        match = re.search(r"max-age=(\d+)", hsts)
        if match:
            max_age = int(match.group(1))
            if max_age < 15552000:
                _add(findings, "LOW", "Weak HSTS max-age", f"max-age={max_age} is below 6 months")
        if "includesubdomains" not in hsts.lower():
            _add(findings, "INFO", "HSTS without includeSubDomains", "HSTS missing includeSubDomains")

    csp = h.get("content-security-policy", "")
    if not csp:
        _add(findings, "MEDIUM", "Missing CSP", "content-security-policy header is missing")
    else:
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            _add(findings, "LOW", "Weak CSP", "CSP contains unsafe-inline or unsafe-eval")

    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        _add(findings, "LOW", "Missing clickjacking protection", "x-frame-options or CSP frame-ancestors missing")

    if "x-content-type-options" not in h:
        _add(findings, "LOW", "Missing MIME sniffing protection", "x-content-type-options missing")

    if "referrer-policy" not in h:
        _add(findings, "INFO", "Missing Referrer-Policy", "referrer-policy header is missing")

    if "permissions-policy" not in h:
        _add(findings, "INFO", "Missing Permissions-Policy", "permissions-policy header is missing")

    if "cross-origin-opener-policy" not in h:
        _add(findings, "INFO", "Missing COOP", "cross-origin-opener-policy missing")

    if "cross-origin-resource-policy" not in h:
        _add(findings, "INFO", "Missing CORP", "cross-origin-resource-policy missing")

    if "cross-origin-embedder-policy" not in h:
        _add(findings, "INFO", "Missing COEP", "cross-origin-embedder-policy missing")

    if "server" in h:
        _add(findings, "INFO", "Server header present", "server header discloses platform", {"server": h.get("server")})

    if "x-powered-by" in h:
        _add(findings, "INFO", "X-Powered-By header present", "x-powered-by discloses framework", {"x-powered-by": h.get("x-powered-by")})

    if "text/html" in (content_type or "") and "cache-control" not in h:
        _add(findings, "INFO", "Missing Cache-Control", "cache-control missing on HTML response")

    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "")
    if acao == "*" and acac.lower() == "true":
        _add(findings, "HIGH", "Insecure CORS", "ACAO=* with credentials enabled")
    elif acao == "*":
        _add(findings, "LOW", "Permissive CORS", "ACAO=*")

    raw_cookie = h.get("set-cookie", "")
    for cookie in _split_set_cookie(raw_cookie):
        cookie_l = cookie.lower()
        if "secure" not in cookie_l:
            _add(findings, "MEDIUM", "Cookie without Secure", "Set-Cookie missing Secure attribute")
        if "httponly" not in cookie_l:
            _add(findings, "MEDIUM", "Cookie without HttpOnly", "Set-Cookie missing HttpOnly attribute")
        if "samesite=" not in cookie_l:
            _add(findings, "LOW", "Cookie without SameSite", "Set-Cookie missing SameSite attribute")

    return findings


def header_fingerprint(headers: Dict[str, str]) -> Dict[str, str]:
    h = normalize_headers(headers)
    keys = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "cross-origin-embedder-policy",
        "access-control-allow-origin",
        "access-control-allow-credentials",
    ]
    return {k: h.get(k, "") for k in keys}


def summarize_findings(findings: List[dict]) -> Dict[str, int]:
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for item in findings or []:
        sev = item.get("severity", "INFO").upper()
        if sev not in summary:
            sev = "INFO"
        summary[sev] += 1
    return summary
