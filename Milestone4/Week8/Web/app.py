import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from Milestone1.Week2.week2_crawler import run_crawler
from Milestone2.Week3.week3_sql_tester import run_sql_tests
from Milestone2.Week4.week4_xss_tester import run_xss_tests
from Milestone3.Week5.week5_misc_security_checks import run_misc_checks
from Milestone3.Week6.week6_idor_access_control import run_idor_tests
from Milestone4.Week7.week7_report_generator import generate_report

app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
RESULTS_DIR = os.path.join("web", "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

@app.route("/", methods=["GET"])
def home():
    return render_template("home.html")

@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip() or "http://localhost:8080"
    crawl_data = run_crawler(target)
    sql_results = run_sql_tests(target)
    xss_results = run_xss_tests(crawl_data)
    misc_results = run_misc_checks(crawl_data)
    idor_results = run_idor_tests(target)
    all_findings = (sql_results or []) + (xss_results or []) + (misc_results or []) + (idor_results or [])
    report_path = generate_report(target, all_findings, save_file=os.path.join(RESULTS_DIR, "latest_report.html"))
    return redirect(url_for("results"))

@app.route("/results", methods=["GET"])
def results():
    return render_template("results.html")

@app.route("/results/download", methods=["GET"])
def download_report():
    return send_from_directory(RESULTS_DIR, "latest_report.html", as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
