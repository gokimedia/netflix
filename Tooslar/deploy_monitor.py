#!/usr/bin/env python3
"""
Next.js Deployment Monitor
Monitors sites for new deployments and alerts immediately

When a new deployment is detected:
1. Downloads new JS files
2. Compares with old version
3. Looks for new endpoints, secrets, vulnerabilities
4. Sends Telegram alert
"""

import requests
import hashlib
import json
import time
import os
import re
from datetime import datetime
from urllib.parse import urlparse
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from security_checks import header_fingerprint

# Configuration
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', 'YOUR_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID', 'YOUR_CHAT_ID')
CHECK_INTERVAL = 300  # 5 minutes
DATA_DIR = Path('./monitor_data')


@dataclass
class MonitorConfig:
    check_interval: int = CHECK_INTERVAL
    data_dir: Path = DATA_DIR
    timeout: int = 15
    retries: int = 2
    backoff_factor: float = 0.3
    verify_ssl: bool = False
    max_js_files: int = 20
    max_js_bytes: int = 2_000_000
    save_js: bool = False
    diff_js: bool = False
    diff_max_bytes: int = 500_000
    user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    verbose: bool = False


class DeploymentMonitor:
    def __init__(self, config: MonitorConfig = None):
        self.config = config or MonitorConfig()
        self.session = self._build_session()
        self.request_count = 0
        self.data_dir = self.config.data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _build_session(self):
        session = requests.Session()
        retry = Retry(
            total=self.config.retries,
            backoff_factor=self.config.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD", "POST"],
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers = {
            'User-Agent': self.config.user_agent,
        }
        session.verify = self.config.verify_ssl
        return session

    def _request(self, method, url, **kwargs):
        kwargs.setdefault("timeout", self.config.timeout)
        try:
            resp = self.session.request(method, url, **kwargs)
            self.request_count += 1
            return resp
        except Exception as e:
            if self.config.verbose:
                print(f"Request error: {url} - {e}")
            return None

    def _site_dir(self, site_id: str) -> Path:
        path = self.data_dir / site_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _save_js_snapshot(self, site_id: str, js_url: str, content: bytes) -> str:
        if not self.config.save_js or not content:
            return ""
        if len(content) > self.config.max_js_bytes:
            return ""
        site_dir = self._site_dir(site_id)
        js_dir = site_dir / "js"
        js_dir.mkdir(parents=True, exist_ok=True)
        name_hash = hashlib.sha1(js_url.encode("utf-8")).hexdigest()[:16]
        filename = f"{name_hash}.js"
        filepath = js_dir / filename
        try:
            filepath.write_bytes(content)
            return str(filepath)
        except Exception:
            return ""

    def _diff_js_files(self, site_id: str, old: dict, new: dict):
        if not self.config.diff_js:
            return []
        diffs = []
        site_dir = self._site_dir(site_id)
        diff_dir = site_dir / "diffs"
        diff_dir.mkdir(parents=True, exist_ok=True)

        for js_url, new_meta in new.get("js_files", {}).items():
            old_meta = old.get("js_files", {}).get(js_url, {})
            if not old_meta:
                continue
            if old_meta.get("hash") == new_meta.get("hash"):
                continue
            old_path = old_meta.get("path")
            new_path = new_meta.get("path")
            if not old_path or not new_path:
                continue
            try:
                old_text = Path(old_path).read_text(encoding="utf-8", errors="replace")
                new_text = Path(new_path).read_text(encoding="utf-8", errors="replace")
                if len(old_text) > self.config.diff_max_bytes or len(new_text) > self.config.diff_max_bytes:
                    continue
                import difflib
                diff = difflib.unified_diff(
                    old_text.splitlines(),
                    new_text.splitlines(),
                    fromfile=old_path,
                    tofile=new_path,
                    lineterm=""
                )
                diff_content = "\n".join(diff)
                if not diff_content:
                    continue
                diff_name = hashlib.sha1(js_url.encode("utf-8")).hexdigest()[:16] + ".diff"
                diff_path = diff_dir / diff_name
                diff_path.write_text(diff_content, encoding="utf-8")
                diffs.append(str(diff_path))
            except Exception:
                continue
        return diffs

    def send_telegram(self, message):
        """Send Telegram notification"""
        if TELEGRAM_BOT_TOKEN == 'YOUR_BOT_TOKEN':
            print(f"[TELEGRAM] {message}")
            return

        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            data = {
                'chat_id': TELEGRAM_CHAT_ID,
                'text': message,
                'parse_mode': 'HTML'
            }
            self._request("POST", url, data=data, timeout=10)
        except Exception as e:
            print(f"Telegram error: {e}")

    def get_site_fingerprint(self, url):
        """Get fingerprint of a site (build ID, JS hashes)"""
        try:
            site_id = urlparse(url).netloc.replace(":", "_")
            resp = self._request("GET", url, timeout=self.config.timeout)
            if not resp:
                return None

            fingerprint = {
                'timestamp': datetime.now().isoformat(),
                'build_id': None,
                'js_files': {},
                'total_size': len(resp.text),
                'content_hash': hashlib.md5(resp.text.encode()).hexdigest(),
                'security_headers': header_fingerprint(resp.headers),
            }

            # Extract build ID
            match = re.search(r'"buildId"\s*:\s*"([^"]+)"', resp.text)
            if match:
                fingerprint['build_id'] = match.group(1)

            # Extract JS file URLs and their hashes
            js_urls = re.findall(r'(/_next/static/[^"\']+\.js)', resp.text)
            js_urls = list(set(js_urls))[:self.config.max_js_files]

            for js_url in js_urls:
                try:
                    full_url = url.rstrip('/') + js_url
                    js_resp = self._request("GET", full_url, timeout=self.config.timeout)
                    if js_resp and js_resp.content:
                        saved_path = self._save_js_snapshot(site_id, js_url, js_resp.content)
                        fingerprint['js_files'][js_url] = {
                            'hash': hashlib.md5(js_resp.content).hexdigest(),
                            'size': len(js_resp.content),
                            'path': saved_path or None,
                        }
                except:
                    pass

            return fingerprint

        except Exception as e:
            print(f"Error fingerprinting {url}: {e}")
            return None

    def load_previous_fingerprint(self, site_id):
        """Load previous fingerprint from disk"""
        fp_file = self.data_dir / f"{site_id}.json"
        if fp_file.exists():
            with open(fp_file, 'r') as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    return None
        return None

    def save_fingerprint(self, site_id, fingerprint):
        """Save fingerprint to disk"""
        fp_file = self.data_dir / f"{site_id}.json"
        with open(fp_file, 'w') as f:
            json.dump(fingerprint, f, indent=2)

    def compare_fingerprints(self, old, new):
        """Compare two fingerprints and find changes"""
        changes = {
            'build_changed': False,
            'new_js_files': [],
            'modified_js_files': [],
            'removed_js_files': [],
            'size_change': 0,
            'diff_files': [],
            'security_header_changes': [],
        }

        if not old:
            return changes

        # Check build ID
        if old.get('build_id') != new.get('build_id'):
            changes['build_changed'] = True

        # Check JS files
        old_files = set(old.get('js_files', {}).keys())
        new_files = set(new.get('js_files', {}).keys())

        changes['new_js_files'] = list(new_files - old_files)
        changes['removed_js_files'] = list(old_files - new_files)

        # Check modified files
        for js_file in old_files & new_files:
            old_hash = old['js_files'][js_file]['hash']
            new_hash = new['js_files'][js_file]['hash']
            if old_hash != new_hash:
                changes['modified_js_files'].append(js_file)

        # Size change
        changes['size_change'] = new.get('total_size', 0) - old.get('total_size', 0)

        # Security header changes
        old_headers = old.get('security_headers', {})
        new_headers = new.get('security_headers', {})
        for key, value in new_headers.items():
            if old_headers.get(key) != value:
                changes['security_header_changes'].append({
                    'header': key,
                    'old': old_headers.get(key, ''),
                    'new': value,
                })

        return changes

    def analyze_new_deployment(self, url, changes):
        """Analyze new deployment for security issues"""
        findings = []

        # If build changed, do deep analysis
        if changes['build_changed'] or changes['new_js_files'] or changes['modified_js_files']:
            try:
                resp = self._request("GET", url, timeout=self.config.timeout)
                if not resp:
                    return findings

                # Check for debug mode
                if 'development' in resp.text.lower() or '__REACT_DEVTOOLS' in resp.text:
                    findings.append("DEBUG MODE DETECTED")

                # Check for source maps
                for js_file in changes['new_js_files'] + changes['modified_js_files']:
                    map_url = url.rstrip('/') + js_file + '.map'
                    try:
                        map_resp = self._request("HEAD", map_url, timeout=self.config.timeout)
                        if map_resp and map_resp.status_code == 200:
                            findings.append(f"SOURCE MAP: {js_file}.map")
                    except:
                        pass

                # Check for exposed env vars
                env_patterns = [
                    r'NEXT_PUBLIC_[A-Z_]+=',
                    r'API_KEY\s*[:=]',
                    r'SECRET\s*[:=]',
                ]
                for pattern in env_patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        findings.append(f"ENV PATTERN: {pattern}")

            except Exception as e:
                print(f"Analysis error: {e}")

        return findings

    def check_site(self, site):
        """Check a single site for deployment changes"""
        url = site['url']
        site_id = site['name'].lower().replace(' ', '_')

        print(f"[{datetime.now().strftime('%H:%M:%S')}] Checking {site['name']}...")

        # Get current fingerprint
        current = self.get_site_fingerprint(url)
        if not current:
            return None

        # Load previous
        previous = self.load_previous_fingerprint(site_id)

        # Compare
        changes = self.compare_fingerprints(previous, current)

        # Check if anything significant changed
        has_changes = (
            changes['build_changed'] or
            changes['new_js_files'] or
            changes['modified_js_files'] or
            changes.get('security_header_changes')
        )

        if has_changes:
            print(f"  [!] DEPLOYMENT DETECTED!")

            if self.config.diff_js and self.config.save_js and previous:
                changes['diff_files'] = self._diff_js_files(site_id, previous, current)

            # Analyze for security issues
            findings = self.analyze_new_deployment(url, changes)

            # Send alert
            message = f"""
<b>NEW DEPLOYMENT DETECTED</b>

<b>Site:</b> {site['name']}
<b>URL:</b> {url}
<b>Bounty:</b> ${site.get('max_bounty', 'Unknown')}

<b>Changes:</b>
- Build Changed: {changes['build_changed']}
- New JS Files: {len(changes['new_js_files'])}
- Modified JS Files: {len(changes['modified_js_files'])}
- Diff Files: {len(changes.get('diff_files', []))}
 - Security Header Changes: {len(changes.get('security_header_changes', []))}

<b>Security Findings:</b>
{chr(10).join(findings) if findings else 'None detected'}

<b>Action:</b> TEST NOW before others!
"""
            self.send_telegram(message)

            # Also print to console
            print(f"  Build: {previous.get('build_id')} -> {current.get('build_id')}")
            print(f"  New files: {changes['new_js_files']}")
            print(f"  Modified: {changes['modified_js_files']}")
            if changes.get('diff_files'):
                print(f"  Diffs: {changes['diff_files']}")
            if changes.get('security_header_changes'):
                print(f"  Security header changes: {changes['security_header_changes']}")
            for f in findings:
                print(f"  FINDING: {f}")

        # Save current fingerprint
        self.save_fingerprint(site_id, current)

        return changes

    def run(self, targets):
        """Run continuous monitoring"""
        print("\n" + "="*60)
        print("Next.js Deployment Monitor")
        print("="*60)
        print(f"Monitoring {len(targets)} sites")
        print(f"Check interval: {self.config.check_interval} seconds")
        print("="*60 + "\n")

        # Initial fingerprint for all sites
        print("Creating initial fingerprints...")
        for site in targets:
            self.check_site(site)
        print("\nInitial fingerprints created. Starting monitoring...\n")

        # Continuous monitoring
        while True:
            try:
                for site in targets:
                    self.check_site(site)
                    time.sleep(2)  # Small delay between sites

                print(f"[{datetime.now().strftime('%H:%M:%S')}] Sleeping {self.config.check_interval}s...")
                time.sleep(self.config.check_interval)

            except KeyboardInterrupt:
                print("\nStopping monitor...")
                break
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(60)


# Example targets
MONITOR_TARGETS = [
    {
        'name': 'Vercel',
        'url': 'https://vercel.com',
        'max_bounty': 15000,
    },
    {
        'name': 'Netflix Jobs',
        'url': 'https://jobs.netflix.com',
        'max_bounty': 15000,
    },
    {
        'name': 'Supabase',
        'url': 'https://supabase.com',
        'max_bounty': 5000,
    },
    {
        'name': 'Linear',
        'url': 'https://linear.app',
        'max_bounty': 5000,
    },
    {
        'name': 'Notion',
        'url': 'https://www.notion.so',
        'max_bounty': 5000,
    },
]


def main():
    global TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
    import argparse

    parser = argparse.ArgumentParser(description="Next.js Deployment Monitor")
    parser.add_argument("--targets", help="Path to JSON file with targets")
    parser.add_argument("--interval", type=int, default=CHECK_INTERVAL, help="Check interval in seconds")
    parser.add_argument("--data-dir", default=str(DATA_DIR), help="Data directory")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout")
    parser.add_argument("--retries", type=int, default=2, help="Retry count")
    parser.add_argument("--backoff", type=float, default=0.3, help="Retry backoff factor")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify TLS certificates")
    parser.add_argument("--max-js", type=int, default=20, help="Max JS files to hash")
    parser.add_argument("--max-js-bytes", type=int, default=2000000, help="Max JS file size to save")
    parser.add_argument("--save-js", action="store_true", help="Save JS snapshots to disk")
    parser.add_argument("--diff-js", action="store_true", help="Generate diffs for modified JS files")
    parser.add_argument("--diff-max-bytes", type=int, default=500000, help="Max JS size to diff")
    parser.add_argument("--telegram-token", default=TELEGRAM_BOT_TOKEN, help="Telegram bot token")
    parser.add_argument("--telegram-chat", default=TELEGRAM_CHAT_ID, help="Telegram chat ID")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # Override Telegram configuration (optional)
    TELEGRAM_BOT_TOKEN = args.telegram_token
    TELEGRAM_CHAT_ID = args.telegram_chat

    targets = MONITOR_TARGETS
    if args.targets:
        try:
            with open(args.targets, "r") as f:
                targets = json.load(f)
        except Exception as e:
            print(f"Failed to load targets: {e}")
            return

    config = MonitorConfig(
        check_interval=args.interval,
        data_dir=Path(args.data_dir),
        timeout=args.timeout,
        retries=args.retries,
        backoff_factor=args.backoff,
        verify_ssl=args.verify_ssl,
        max_js_files=args.max_js,
        max_js_bytes=args.max_js_bytes,
        save_js=args.save_js,
        diff_js=args.diff_js,
        diff_max_bytes=args.diff_max_bytes,
        verbose=args.verbose,
    )

    monitor = DeploymentMonitor(config)
    monitor.run(targets)


if __name__ == '__main__':
    main()
