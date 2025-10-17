import json
import re
from urllib.parse import urlparse, urljoin
import requests

COMMON_FILES = [
    ".git/",
    ".env",
    "config.php",
    "phpinfo.php",
    "robots.txt",
    "backup.zip",
    "db.sql",
    "admin/",
    ".DS_Store",
]

SEC_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]

def _safe_get_base_url(crawl_data, default="http://localhost:8080"):
    if isinstance(crawl_data, dict):
        if isinstance(crawl_data.get("start_url"), str):
            return crawl_data["start_url"].rstrip("/")
        if isinstance(crawl_data.get("pages"), dict) and crawl_data["pages"]:
            return list(crawl_data["pages"].keys())[0].rstrip("/")
        if isinstance(crawl_data.get("pages"), list):
            for item in crawl_data["pages"]:
                if isinstance(item, str) and item.startswith(("http://", "https://")):
                    return item.rstrip("/")
    if isinstance(crawl_data, list):
        for item in crawl_data:
            if isinstance(item, str) and item.startswith(("http://", "https://")):
                return item.rstrip("/")
    if isinstance(crawl_data, str) and crawl_data.startswith(("http://", "https://")):
        return crawl_data.rstrip("/")
    return default.rstrip("/")

def _derive_origin(url):
    p = urlparse(url)
    scheme = p.scheme or "http"
    return f"{scheme}://{p.netloc}"

def _check_common_files(base_origin):
    findings = []
    for path in COMMON_FILES:
        url = urljoin(base_origin + "/", path)
        try:
            res = requests.get(url, timeout=10, allow_redirects=True)
            if res.status_code == 200:
                evidence = f"HTTP {res.status_code}"
                if re.search(r"(Index of|Directory listing|Parent Directory)", res.text, re.I):
                    evidence += " with directory listing"
                findings.append({
                    "type": "Sensitive File",
                    "endpoint": url,
                    "param": "-",
                    "payload": path,
                    "evidence": evidence,
                    "severity": "Medium",
                })
        except Exception:
            continue
    return findings

def _check_security_headers(sample_url):
    findings = []
    try:
        res = requests.get(sample_url, timeout=10, allow_redirects=True)
        headers = {k.lower(): v for k, v in res.headers.items()}
        for header in SEC_HEADERS:
            if header.lower() not in headers:
                findings.append({
                    "type": "Missing Security Header",
                    "endpoint": sample_url,
                    "param": header,
                    "payload": "-",
                    "evidence": f"{header} not present",
                    "severity": "Low",
                })
    except Exception:
        pass
    return findings

def _pick_representative_page(crawl_data, base_origin):
    if isinstance(crawl_data, dict) and isinstance(crawl_data.get("pages"), dict):
        for u in crawl_data["pages"].keys():
            if isinstance(u, str) and u.startswith(("http://", "https://")):
                return u
    if isinstance(crawl_data, dict) and isinstance(crawl_data.get("pages"), list):
        for u in crawl_data["pages"]:
            if isinstance(u, str) and u.startswith(("http://", "https://")):
                return u
    if isinstance(crawl_data, list):
        for u in crawl_data:
            if isinstance(u, str) and u.startswith(("http://", "https://")):
                return u
    return base_origin

def run_misc_checks(crawl_data=None, save_file="week5_misc_results.json"):
    print("[+] Running Miscellaneous Security Checks...")
    base_url = _safe_get_base_url(crawl_data, default="http://localhost:8080")
    base_origin = _derive_origin(base_url)
    findings = []
    findings.extend(_check_common_files(base_origin))
    sample_page = _pick_representative_page(crawl_data, base_origin)
    findings.extend(_check_security_headers(sample_page))
    try:
        with open(save_file, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)
    except Exception:
        pass
    return findings