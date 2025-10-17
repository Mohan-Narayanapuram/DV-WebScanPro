import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATE_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>WebScanPro Report</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://unpkg.com/modern-css-reset/dist/reset.min.css" rel="stylesheet">
  <style>
    body { font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; color: #111; background:#f6f7fb; }
    .container { max-width: 1100px; margin: 40px auto; padding: 0 16px; }
    .card { background: #fff; border-radius: 12px; box-shadow: 0 6px 18px rgba(0,0,0,0.06); padding: 20px; margin-bottom: 24px; }
    .header { display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; }
    .title { font-size: 22px; font-weight: 700; }
    .meta { color:#666; font-size: 14px; }
    .badges { display:flex; gap:8px; }
    .badge { padding: 6px 10px; border-radius: 999px; font-size: 12px; font-weight:600; }
    .b-high { background:#ffe3e3; color:#b00020; }
    .b-medium { background:#fff2d6; color:#8a5b00; }
    .b-low { background:#e8f5e9; color:#2e7d32; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 10px 12px; border-bottom:1px solid #eee; text-align:left; font-size: 14px; }
    th { background:#fafbfe; font-weight:700; }
    tr.high td { background:#fff5f5; }
    tr.medium td { background:#fff9ec; }
    tr.low td { background:#f3fbf4; }
    .btn { display:inline-block; padding:10px 14px; background:#111; color:#fff; text-decoration:none; border-radius:8px; font-weight:600; }
    .btn:focus, .btn:hover { opacity:.9; }
    canvas { max-width: 480px; }
  </style>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="header">
        <div>
          <div class="title">WebScanPro Scan Report</div>
          <div class="meta">Target: {{ target }} • Date: {{ date }}</div>
        </div>
        <div class="badges">
          <span class="badge b-high">High: {{ stats.high }}</span>
          <span class="badge b-medium">Medium: {{ stats.medium }}</span>
          <span class="badge b-low">Low: {{ stats.low }}</span>
        </div>
      </div>
      <div style="display:flex; gap:24px; flex-wrap:wrap; align-items:center;">
        <canvas id="severityChart" width="480" height="480"></canvas>
        <div>
          <p style="color:#444;max-width:520px">
            Summary of vulnerabilities detected by WebScanPro across modules (SQLi, XSS, IDOR, misc). Rows are color-coded by severity.
          </p>
          <a class="btn" href="{{ download_href }}">Download Report</a>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="title" style="margin-bottom:10px">Findings</div>
      <table>
        <thead>
          <tr>
            <th>Type</th>
            <th>Endpoint</th>
            <th>Param</th>
            <th>Payload</th>
            <th>Evidence</th>
            <th>Severity</th>
          </tr>
        </thead>
        <tbody>
          {% for f in findings %}
          <tr class="{{ f.row_class }}">
            <td>{{ f.type }}</td>
            <td>{{ f.endpoint }}</td>
            <td>{{ f.param }}</td>
            <td>{{ f.payload }}</td>
            <td>{{ f.evidence }}</td>
            <td>{{ f.severity }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  <script>
    const ctx = document.getElementById('severityChart').getContext('2d');
    const severityData = {
      labels: ['High', 'Medium', 'Low'],
      datasets: [{
         [{{ stats.high }}, {{ stats.medium }}, {{ stats.low }}],
        backgroundColor: ['#e53935', '#fb8c00', '#43a047'],
        borderWidth: 0
      }]
    };
    new Chart(ctx, { type: 'pie',  severityData });
  </script>
</body>
</html>
"""

def _severity_from_type(t):
    t = (t or "").lower()
    if "sqli" in t or "xss" in t:
        return "High"
    if "idor" in t or "sensitive" in t or "missing security header" in t:
        return "Medium"
    return "Low"

def _row_class(sev):
    s = (sev or "").lower()
    if s == "high": return "high"
    if s == "medium": return "medium"
    return "low"

def generate_report(target_url, findings, save_file="week7_report.html"):
    cleaned = []
    for f in findings or []:
        item = {
            "type": f.get("type", ""),
            "endpoint": f.get("endpoint", ""),
            "param": f.get("param", ""),
            "payload": f.get("payload", ""),
            "evidence": f.get("evidence", ""),
            "severity": f.get("severity") or _severity_from_type(f.get("type")),
        }
        item["row_class"] = _row_class(item["severity"])
        cleaned.append(item)

    stats = {"high": 0, "medium": 0, "low": 0}
    for f in cleaned:
        k = (f["severity"] or "low").lower()
        if k in stats:
            stats[k] += 1

    env = Environment(loader=FileSystemLoader(os.getcwd()), autoescape=select_autoescape(["html", "xml"]))
    html = env.from_string(TEMPLATE_HTML).render(
        target=target_url,
        date=datetime.now().strftime("%Y-%m-%d %H:%M"),
        findings=cleaned,
        stats=stats,
        download_href=os.path.basename(save_file),
    )

    with open(save_file, "w", encoding="utf-8") as f:
        f.write(html)

    return os.path.abspath(save_file)
