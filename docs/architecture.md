# WebScanPro Architecture

WebScanPro is designed as a modular security scanning framework.  
The architecture is organized around **milestones** and **weekly modules**, with each module implementing a distinct security capability.  

## High-Level Components
- **Main Orchestrator (main.py):**
  - Entry point that sequentially runs all modules.
  - Aggregates results from crawler, SQLi, XSS, Misc, and IDOR.
  - Triggers report generation.

- **Modules (Milestone1 → Milestone4):**
  - Week 1–2: Setup and Web Crawler
  - Week 3–4: SQL Injection and XSS
  - Week 5–6: Miscellaneous checks and IDOR
  - Week 7–8: Report Generation and Flask Frontend

- **Report Generator:**
  - Produces HTML reports using Jinja2 templates.
  - Displays vulnerabilities with severity levels and a Chart.js visualization.

- **Flask Frontend:**
  - Provides a simple web UI for inputting targets and running scans.
  - Displays results and allows report download.

## Data Flow
1. **Crawler** collects forms, endpoints, and metadata.
2. **Vulnerability modules** (SQLi, XSS, etc.) test targets using crawler output.
3. **Findings** are stored in JSON files for persistence.
4. **Report Generator** aggregates results and produces a single HTML report.
5. **Frontend (Flask)** interacts with main.py to display scan results.

## Deployment
- Runs locally with Python virtual environment.
- Packaged with Docker for portability.
- Exposed as a web service on port 8000 when containerized.
