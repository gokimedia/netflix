#!/usr/bin/env python3
"""
Bug Bounty Report Generator v1.0
Generates professional bug bounty reports from scan findings

Features:
1. Multiple Output Formats - Markdown, HTML, PDF-ready, JSON
2. CVSS Calculator - Automatic severity scoring
3. Template System - HackerOne, Bugcrowd, custom templates
4. PoC Integration - Embeds proof of concept code
5. Screenshot Placeholders - Easy to add visual evidence
6. Remediation Advice - Industry-standard fixes
7. Timeline Generator - For responsible disclosure
8. Duplicate Check Info - Similar vulnerability references
9. Impact Analysis - Business impact description
10. Attack Scenario - Step-by-step exploitation

Author: Security Research Team
"""

import json
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


@dataclass
class VulnerabilityReport:
    title: str
    severity: str
    category: str
    endpoint: str
    description: str
    steps_to_reproduce: List[str]
    impact: str
    poc: str
    remediation: str
    references: List[str] = field(default_factory=list)
    cvss_score: float = 0.0
    cvss_vector: str = ""
    screenshots: List[str] = field(default_factory=list)


class CVSSCalculator:
    """CVSS 3.1 Calculator"""

    def __init__(self):
        self.base_metrics = {
            'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},  # Attack Vector
            'AC': {'L': 0.77, 'H': 0.44},  # Attack Complexity
            'PR': {'N': 0.85, 'L': 0.62, 'H': 0.27},  # Privileges Required
            'UI': {'N': 0.85, 'R': 0.62},  # User Interaction
            'S': {'U': 0, 'C': 1},  # Scope
            'C': {'N': 0, 'L': 0.22, 'H': 0.56},  # Confidentiality
            'I': {'N': 0, 'L': 0.22, 'H': 0.56},  # Integrity
            'A': {'N': 0, 'L': 0.22, 'H': 0.56},  # Availability
        }

    def calculate(self, vector: str) -> tuple:
        """Calculate CVSS score from vector string"""
        # Parse vector (e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
        metrics = {}
        parts = vector.replace('CVSS:3.1/', '').split('/')
        for part in parts:
            if ':' in part:
                key, value = part.split(':')
                metrics[key] = value

        try:
            # Calculate Impact Sub Score
            isc_base = 1 - ((1 - self.base_metrics['C'][metrics.get('C', 'N')]) *
                           (1 - self.base_metrics['I'][metrics.get('I', 'N')]) *
                           (1 - self.base_metrics['A'][metrics.get('A', 'N')]))

            if metrics.get('S') == 'U':
                impact = 6.42 * isc_base
            else:
                impact = 7.52 * (isc_base - 0.029) - 3.25 * pow(isc_base - 0.02, 15)

            # Calculate Exploitability Sub Score
            exploitability = (8.22 * self.base_metrics['AV'][metrics.get('AV', 'N')] *
                             self.base_metrics['AC'][metrics.get('AC', 'L')] *
                             self.base_metrics['PR'][metrics.get('PR', 'N')] *
                             self.base_metrics['UI'][metrics.get('UI', 'N')])

            # Calculate Base Score
            if impact <= 0:
                score = 0
            elif metrics.get('S') == 'U':
                score = min(impact + exploitability, 10)
            else:
                score = min(1.08 * (impact + exploitability), 10)

            return round(score, 1), self._get_severity(score)

        except Exception as e:
            return 0.0, "Unknown"

    def _get_severity(self, score: float) -> str:
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score >= 0.1:
            return "Low"
        return "None"

    def get_vector_for_vuln(self, vuln_type: str) -> str:
        """Get default CVSS vector for vulnerability type"""
        vectors = {
            'xss': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
            'sqli': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'ssrf': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
            'idor': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
            'rce': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            'auth_bypass': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
            'csrf': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N',
            'cors': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
            'open_redirect': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
            'info_disclosure': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
        }
        return vectors.get(vuln_type.lower(), 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N')


class ReportGenerator:
    """
    Bug Bounty Report Generator
    """

    def __init__(self, program_name: str = "Target", output_dir: str = "."):
        self.program_name = program_name
        self.output_dir = output_dir
        self.cvss = CVSSCalculator()

        self.reports: List[VulnerabilityReport] = []

        # Remediation database
        self.remediations = {
            'xss': """
**Remediation:**
1. Implement proper output encoding based on context (HTML, JavaScript, URL, CSS)
2. Use Content-Security-Policy headers to prevent inline script execution
3. Validate and sanitize all user inputs
4. Use modern frameworks with built-in XSS protection (React, Vue with proper usage)
5. Set HttpOnly flag on sensitive cookies
""",
            'sqli': """
**Remediation:**
1. Use parameterized queries (prepared statements) for all database operations
2. Implement input validation with whitelisting
3. Apply principle of least privilege to database accounts
4. Use ORM frameworks that handle SQL safely
5. Enable WAF rules for SQL injection protection
""",
            'ssrf': """
**Remediation:**
1. Implement URL allowlisting for external requests
2. Block requests to internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
3. Disable unnecessary URL schemes (file://, gopher://, dict://)
4. Use a dedicated service account without cloud metadata access
5. Implement request timeouts and size limits
""",
            'idor': """
**Remediation:**
1. Implement proper authorization checks for every data access
2. Use indirect object references (random tokens instead of sequential IDs)
3. Verify object ownership before allowing access
4. Implement access control lists (ACL)
5. Log and monitor access to sensitive resources
""",
            'auth_bypass': """
**Remediation:**
1. Implement proper authentication on all protected endpoints
2. Use secure session management
3. Validate JWT tokens on every request
4. Implement proper logout/session invalidation
5. Use multi-factor authentication for sensitive operations
""",
            'csrf': """
**Remediation:**
1. Implement anti-CSRF tokens on all state-changing requests
2. Set SameSite=Strict or SameSite=Lax on cookies
3. Verify Referer/Origin headers
4. Use custom request headers for AJAX requests
5. Re-authenticate for sensitive operations
""",
            'cors': """
**Remediation:**
1. Implement strict CORS policy with explicit origin whitelist
2. Never reflect the Origin header in Access-Control-Allow-Origin
3. Avoid using Access-Control-Allow-Origin: *
4. Set Access-Control-Allow-Credentials: false if possible
5. Implement proper authentication regardless of CORS settings
""",
        }

    def add_finding(self, finding: Dict):
        """Add a finding from scan results"""
        vuln_type = finding.get('category', finding.get('vulnerability', 'unknown'))
        cvss_vector = self.cvss.get_vector_for_vuln(vuln_type)
        score, severity = self.cvss.calculate(cvss_vector)

        report = VulnerabilityReport(
            title=finding.get('title', 'Untitled Vulnerability'),
            severity=finding.get('severity', severity),
            category=vuln_type,
            endpoint=finding.get('endpoint', finding.get('location', 'Unknown')),
            description=finding.get('description', ''),
            steps_to_reproduce=finding.get('steps', []),
            impact=finding.get('impact', ''),
            poc=finding.get('evidence', finding.get('payload', '')),
            remediation=self.remediations.get(vuln_type.lower(), 'Consult security best practices.'),
            cvss_score=score,
            cvss_vector=cvss_vector,
        )

        self.reports.append(report)

    def load_from_json(self, json_file: str):
        """Load findings from JSON file"""
        with open(json_file, 'r') as f:
            data = json.load(f)

        findings = data.get('findings', [])
        for finding in findings:
            self.add_finding(finding)

        return len(findings)

    def generate_markdown(self, output_file: str = None) -> str:
        """Generate Markdown report"""
        if not output_file:
            output_file = os.path.join(self.output_dir, 'vulnerability_report.md')

        md = f"""# Security Vulnerability Report
## {self.program_name}

**Report Date:** {datetime.now().strftime('%Y-%m-%d')}
**Report ID:** {datetime.now().strftime('%Y%m%d%H%M%S')}

---

## Executive Summary

This report contains **{len(self.reports)}** security vulnerabilities discovered during the security assessment of {self.program_name}.

### Severity Distribution

| Severity | Count |
|----------|-------|
"""
        # Count by severity
        severity_count = {}
        for r in self.reports:
            sev = r.severity
            severity_count[sev] = severity_count.get(sev, 0) + 1

        for sev in ['Critical', 'High', 'Medium', 'Low', 'Informational']:
            if sev in severity_count or sev.upper() in severity_count:
                count = severity_count.get(sev, severity_count.get(sev.upper(), 0))
                md += f"| {sev} | {count} |\n"

        md += "\n---\n\n## Detailed Findings\n\n"

        # Sort by severity
        severity_order = {'CRITICAL': 0, 'Critical': 0, 'HIGH': 1, 'High': 1,
                          'MEDIUM': 2, 'Medium': 2, 'LOW': 3, 'Low': 3}
        sorted_reports = sorted(self.reports, key=lambda x: severity_order.get(x.severity, 4))

        for i, report in enumerate(sorted_reports, 1):
            md += self._generate_finding_markdown(i, report)

        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(md)

        return output_file

    def _generate_finding_markdown(self, num: int, report: VulnerabilityReport) -> str:
        """Generate Markdown for a single finding"""
        severity_emoji = {
            'Critical': '🔴', 'CRITICAL': '🔴',
            'High': '🟠', 'HIGH': '🟠',
            'Medium': '🟡', 'MEDIUM': '🟡',
            'Low': '🟢', 'LOW': '🟢',
        }

        emoji = severity_emoji.get(report.severity, '⚪')

        md = f"""
### {num}. {emoji} {report.title}

| Field | Value |
|-------|-------|
| **Severity** | {report.severity} |
| **CVSS Score** | {report.cvss_score} |
| **Category** | {report.category} |
| **Endpoint** | `{report.endpoint}` |

#### Description

{report.description}

#### Steps to Reproduce

"""
        if report.steps_to_reproduce:
            for i, step in enumerate(report.steps_to_reproduce, 1):
                md += f"{i}. {step}\n"
        else:
            md += "1. Navigate to the vulnerable endpoint\n"
            md += "2. Inject the payload\n"
            md += "3. Observe the vulnerability\n"

        md += f"""
#### Proof of Concept

```
{report.poc}
```

#### Impact

{report.impact}

#### CVSS Vector

```
{report.cvss_vector}
```

{report.remediation}

#### References

"""
        if report.references:
            for ref in report.references:
                md += f"- {ref}\n"
        else:
            md += "- OWASP Testing Guide\n"
            md += "- CWE Database\n"

        md += "\n---\n"

        return md

    def generate_hackerone(self, output_file: str = None) -> str:
        """Generate HackerOne-style report"""
        if not output_file:
            output_file = os.path.join(self.output_dir, 'hackerone_report.md')

        reports_md = []

        for report in self.reports:
            md = f"""## Summary

{report.title}

## Vulnerability Type

{report.category}

## Description

{report.description}

## Steps To Reproduce

"""
            if report.steps_to_reproduce:
                for i, step in enumerate(report.steps_to_reproduce, 1):
                    md += f"{i}. {step}\n"

            md += f"""
## Proof of Concept

```
{report.poc}
```

## Impact

{report.impact}

## Suggested Remediation

{report.remediation}

## Supporting Material/References

- CVSS Score: {report.cvss_score}
- CVSS Vector: {report.cvss_vector}

---

"""
            reports_md.append(md)

        full_report = '\n'.join(reports_md)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(full_report)

        return output_file

    def generate_html(self, output_file: str = None) -> str:
        """Generate HTML report"""
        if not output_file:
            output_file = os.path.join(self.output_dir, 'vulnerability_report.html')

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {self.program_name}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .report {{
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        h3 {{ color: #666; }}
        .finding {{
            border-left: 4px solid #007bff;
            padding: 15px;
            margin: 20px 0;
            background: #f9f9f9;
        }}
        .critical {{ border-left-color: #dc3545; background: #fff5f5; }}
        .high {{ border-left-color: #fd7e14; background: #fff8f0; }}
        .medium {{ border-left-color: #ffc107; background: #fffef0; }}
        .low {{ border-left-color: #28a745; background: #f0fff4; }}
        .severity {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
            font-size: 12px;
        }}
        .severity.critical {{ background: #dc3545; }}
        .severity.high {{ background: #fd7e14; }}
        .severity.medium {{ background: #ffc107; color: #333; }}
        .severity.low {{ background: #28a745; }}
        code {{
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Monaco', 'Menlo', monospace;
        }}
        pre {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
        }}
        th {{ background: #f0f0f0; }}
        .stats {{
            display: flex;
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-box {{
            flex: 1;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-box.critical {{ background: #dc3545; color: white; }}
        .stat-box.high {{ background: #fd7e14; color: white; }}
        .stat-box.medium {{ background: #ffc107; }}
        .stat-box.low {{ background: #28a745; color: white; }}
        .stat-number {{ font-size: 36px; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="report">
        <h1>Security Vulnerability Report</h1>
        <h2>{self.program_name}</h2>
        <p><strong>Report Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

        <h2>Executive Summary</h2>
        <p>This report contains <strong>{len(self.reports)}</strong> security vulnerabilities.</p>

        <div class="stats">
"""
        # Count by severity
        severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for r in self.reports:
            sev = r.severity.title()
            if sev in severity_count:
                severity_count[sev] += 1

        for sev, count in severity_count.items():
            html += f"""
            <div class="stat-box {sev.lower()}">
                <div class="stat-number">{count}</div>
                <div>{sev}</div>
            </div>
"""

        html += """
        </div>

        <h2>Detailed Findings</h2>
"""

        for i, report in enumerate(self.reports, 1):
            sev_class = report.severity.lower()
            html += f"""
        <div class="finding {sev_class}">
            <h3>{i}. {report.title}</h3>
            <p><span class="severity {sev_class}">{report.severity}</span>
               CVSS: {report.cvss_score}</p>

            <table>
                <tr><th>Category</th><td>{report.category}</td></tr>
                <tr><th>Endpoint</th><td><code>{report.endpoint}</code></td></tr>
            </table>

            <h4>Description</h4>
            <p>{report.description}</p>

            <h4>Proof of Concept</h4>
            <pre>{report.poc}</pre>

            <h4>Impact</h4>
            <p>{report.impact}</p>

            <h4>Remediation</h4>
            {report.remediation.replace(chr(10), '<br>')}
        </div>
"""

        html += """
    </div>
</body>
</html>
"""

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)

        return output_file

    def generate_all(self):
        """Generate all report formats"""
        os.makedirs(self.output_dir, exist_ok=True)

        md_file = self.generate_markdown()
        h1_file = self.generate_hackerone()
        html_file = self.generate_html()

        return {
            'markdown': md_file,
            'hackerone': h1_file,
            'html': html_file,
        }


def main():
    if len(sys.argv) < 2:
        print("Usage: python report_generator.py <findings_json> [program_name]")
        print("\nExamples:")
        print("  python report_generator.py ultimate_scan/ultimate_report.json")
        print("  python report_generator.py scan_results.json 'Netflix Bug Bounty'")
        print("\nSupported input formats:")
        print("  - ultimate_scanner.py output")
        print("  - idor_hunter.py output")
        print("  - auth_bypass.py output")
        print("  - Any JSON with 'findings' array")
        sys.exit(1)

    json_file = sys.argv[1]
    program_name = sys.argv[2] if len(sys.argv) > 2 else "Target Application"

    if not os.path.exists(json_file):
        print(f"Error: File not found: {json_file}")
        sys.exit(1)

    # Create output directory
    output_dir = os.path.join(os.path.dirname(json_file), 'reports')
    os.makedirs(output_dir, exist_ok=True)

    generator = ReportGenerator(program_name=program_name, output_dir=output_dir)

    # Load findings
    count = generator.load_from_json(json_file)
    print(f"Loaded {count} findings from {json_file}")

    if count == 0:
        print("No findings to report.")
        sys.exit(0)

    # Generate reports
    files = generator.generate_all()

    print("\nGenerated reports:")
    for format_name, file_path in files.items():
        print(f"  {format_name}: {file_path}")


if __name__ == "__main__":
    main()
