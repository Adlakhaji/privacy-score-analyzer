from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
from scanner import analyze_website, calculate_privacy_score

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan_website():

    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    parsed_url = urlparse(url)

    if parsed_url.scheme not in ("http", "https") or not parsed_url.hostname:
        return jsonify({
            "error": "Please enter a valid HTTP or HTTPS URL."
        }), 400

    try:
        scan_results = analyze_website(url)

        if "Error" in scan_results:
            return jsonify(scan_results), 400

        score_results = calculate_privacy_score(scan_results)

        if "Error" in score_results:
            return jsonify(score_results), 400

        return jsonify({
            "scan_results": scan_results,
            "score_results": score_results
        })

    except Exception:
        app.logger.exception("Website scanning failed")

        return jsonify({
            "error": "An unexpected error occurred during scanning."
        }), 500
