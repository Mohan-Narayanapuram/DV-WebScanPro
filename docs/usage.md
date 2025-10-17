# Usage Guide

This document explains how to run WebScanPro both locally and with Docker.

## Running Locally
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/webscanpro.git
   cd webscanpro ```

2.	Create a virtual environment and install dependencies:
   ``` bash
   python3 -m venv webscanpro_env
   source webscanpro_env/bin/activate
   pip install -r requirements.txt
   ```

3.	Start DVWA (Damn Vulnerable Web Application) locally or in Docker.

4.	Run the scanner:
   ``` bash
   python3 main.py
   ```

5. Reports will be generated in the project directory as .html files.


## Running with Flask Frontend

1.	From the root directory, run:
   ``` bash
   python3 app.py
   ```

2. Open your browser and visit:
   ```
   http://localhost:8000
   ```

3. Enter a target URL, run the scan, and view results.

## Running with Docker
1. Build the image:
   ``` bash
   docker build -t webscanpro:latest .
   ```

2. Run the container:
   ``` bash
   docker run --rm -p 8000:8000 webscanpro:latest
   ```

3. Access the web interface at:
   ``` bash
   http://localhost:8000
   ```

## Outputs
- JSON Result Files:
  Each module stores its findings as JSON (e.g., week3_sql_results.json, week_xss_results.json).
  
- Consolidated HTML Report:
  Generated in the root or web/results/folder, with:
  - Color-coded severities
  - Badges for High/Medium/Low risks
  - A pie chart visualization of vulnerabilities

- Flask Results Page:
  Shows scan summary, findings, and a link to download the latest report.
