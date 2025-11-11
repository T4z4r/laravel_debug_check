#!/usr/bin/env python3
"""
Laravel Debug & Error-Page Leak Tester
------------------------------------
Features
* Detect APP_DEBUG=true (full stack trace page)
* Detect Laravel version in debug or error pages
* Check common error codes (404, 403, 500, 422, 419)
* Optional word-list of paths to increase coverage
* Colored console output
* CSV report (--report)

Usage
    python3 laravel_debug_check.py https://example.com [--paths paths.txt] [--report report.csv]

Author:  Your Name
Date:    2025-11-11
"""

import argparse
import csv
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

import requests

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
TIMEOUT = 8
MAX_WORKERS = 20

# HTTP codes that Laravel may render a custom error page for
ERROR_CODES = [400, 401, 403, 404, 405, 419, 422, 500, 503]

# Signatures that indicate a Laravel debug page
DEBUG_SIGNATURES = [
    b'Whoops, looks like something went wrong.',
    b'Laravel Development Page',
    b'Stack trace',
    b'Illuminate\\Foundation',
    b'APP_DEBUG',
]

# Signatures that leak Laravel version even when DEBUG=false
VERSION_SIGNATURES = [
    b'Laravel Framework',
    b'Laravel v',
    b'X-Laravel',
    b'"laravel_version"',
]

# --------------------------------------------------------------------------- #
# Helper classes
# --------------------------------------------------------------------------- #
class bcolors:
    OK = '\033[92m'
    WARN = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# --------------------------------------------------------------------------- #
# Core functions
# --------------------------------------------------------------------------- #
def is_laravel_debug_page(content: bytes) -> bool:
    return any(sig in content for sig in DEBUG_SIGNATURES)

def extract_laravel_version(content: bytes) -> Optional[str]:
    import re
    m = re.search(br'Laravel(?: Framework)?[\s-]*v?([\d\.]+)', content, re.I)
    if m:
        return m.group(1).decode(errors='ignore')
    return None

def trigger_error(url: str, code: int, session: requests.Session) -> requests.Response:
    """
    Force Laravel to return a specific status code.
    - 404 → non-existent path
    - 403 → .git/HEAD (most Laravel apps block it)
    - 419 → POST without CSRF (only works on POST-able pages)
    - 422 → POST with invalid _token
    - 500 → provoke an exception (division by zero)
    """
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    if code == 404:
        return session.get(f"{base}/__laravel_debug_check_404_{code}", timeout=TIMEOUT)

    if code == 403:
        return session.get(f"{base}/.env", timeout=TIMEOUT)  # usually blocked → 403

    if code == 500:
        # Try to trigger a PHP exception via a crafted query string
        return session.get(f"{base}/?exploit=1/0", timeout=TIMEOUT)

    if code in (419, 422):
        # Need a POST-able page; fall back to root
        return session.post(base, data={"_token": "invalid"}, timeout=TIMEOUT)

    # Generic – just request a random non-existent resource
    return session.get(f"{base}/__laravel_debug_check_{code}", timeout=TIMEOUT)

def check_target(target: str, path: str, session: requests.Session,
                 report_rows: List[dict]) -> None:
    url = urllib.parse.urljoin(target.rstrip('/') + '/', path.lstrip('/'))
    try:
        resp = session.get(url, timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException as e:
        print(f"{bcolors.FAIL}[-] {url}  →  REQUEST ERROR: {e}{bcolors.ENDC}")
        return

    status = resp.status_code
    content = resp.content

    finding = {
        "url": url,
        "status": status,
        "debug": False,
        "version": None,
        "note": ""
    }

    # 1. Debug page detection
    if is_laravel_debug_page(content):
        finding["debug"] = True
        ver = extract_laravel_version(content)
        finding["version"] = ver
        print(f"{bcolors.FAIL}[!] DEBUG PAGE FOUND: {url} (status {status}){bcolors.ENDC}")
        if ver:
            print(f"    Laravel version ≈ {ver.decode()}")
    else:
        # 2. Even without DEBUG, some error pages leak version
        ver = extract_laravel_version(content)
        if ver:
            finding["version"] = ver.decode()
            print(f"{bcolors.WARN}[!] VERSION LEAK: {url} → Laravel {ver.decode()}{bcolors.ENDC}")

    # 3. Trigger specific error codes on the root (only once per target)
    if path == "/":
        for code in ERROR_CODES:
            try:
                r = trigger_error(target, code, session)
                if is_laravel_debug_page(r.content):
                    print(f"{bcolors.FAIL}[!] DEBUG on forced {code}: {r.url}{bcolors.ENDC}")
                    finding["note"] += f"DEBUG_{code};"
                elif extract_laravel_version(r.content):
                    v = extract_laravel_version(r.content)
                    print(f"{bcolors.WARN}[!] Version leak on {code}: {v.decode()}{bcolors.ENDC}")
                    finding["note"] += f"VER_{code};"
            except Exception:
                pass

    report_rows.append(finding)


def load_paths(file_path: str) -> List[str]:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"{bcolors.WARN}Path file not found: {file_path}{bcolors.ENDC}")
        return []

# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main():
    parser = argparse.ArgumentParser(
        description="Laravel APP_DEBUG & Error-Page Leak Tester",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("target", help="Base URL (e.g. https://example.com)")
    parser.add_argument("-p", "--paths", help="File with additional paths (one per line)")
    parser.add_argument("-r", "--report", help="CSV report output file")
    parser.add_argument("--threads", type=int, default=MAX_WORKERS,
                        help="Concurrent threads")
    args = parser.parse_args()

    target = args.target.rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; LaravelDebugCheck/1.0)"
    })

    paths = ["/"]  # always check root
    if args.paths:
        paths += load_paths(args.paths)

    report_rows = []
    print(f"{bcolors.OK}[*] Scanning {target} with {len(paths)} path(s){bcolors.ENDC}\n")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(check_target, target, p, session, report_rows): p
            for p in paths
        }
        for future in as_completed(futures):
            future.result()  # propagate exceptions

    # ------------------------------------------------------------------- #
    # Reporting
    # ------------------------------------------------------------------- #
    if args.report:
        keys = ["url", "status", "debug", "version", "note"]
        with open(args.report, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=keys)
            writer.writeheader()
            for row in report_rows:
                writer.writerow(row)
        print(f"\n{bcolors.OK}[+] CSV report saved to {args.report}{bcolors.ENDC}")

    # Summary
    debug_cnt = sum(1 for r in report_rows if r["debug"])
    ver_cnt = sum(1 for r in report_rows if r["version"])
    print(f"\n{bcolors.BOLD}=== SUMMARY ==={bcolors.ENDC}")
    print(f"  Debug pages found : {debug_cnt}")
    print(f"  Version leaks     : {ver_cnt}")
    if debug_cnt:
        print(f"{bcolors.FAIL}  → APP_DEBUG is likely TRUE – immediate remediation needed!{bcolors.ENDC}")
    else:
        print(f"{bcolors.OK}  → No obvious debug page detected.{bcolors.ENDC}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{bcolors.WARN}Interrupted by user.{bcolors.ENDC}")
        sys.exit(1)