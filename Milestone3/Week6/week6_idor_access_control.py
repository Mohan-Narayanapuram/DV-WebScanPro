import requests
import json

test_ids = ["1", "2", "9999"]

def run_idor_tests(base_url="http://localhost:8080", save_file="week6_idor_results.json"):
    print("[+] Running IDOR / Access Control Tests...")
    findings = []

    for tid in test_ids:
        url = f"{base_url}/profile.php?id={tid}"
        try:
            res = requests.get(url, timeout=10)
            if res.status_code == 200 and "Profile" in res.text:
                print(f"[!] Possible IDOR at {url}")
                findings.append({
                    "type": "IDOR",
                    "endpoint": url,
                    "param": "id",
                    "payload": tid,
                    "evidence": "Profile data visible"
                })
        except Exception as e:
            print(f"[-] Error testing {url}: {e}")

    with open(save_file, "w") as f:
        json.dump(findings, f, indent=2)

    return findings