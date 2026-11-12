from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse

from .scanner import analyze_website, calculate_privacy_score

app = Flask(
    __name__,
    template_folder="../frontend",
    static_folder="../frontend",
    static_url_path="/static"
)

# HOME PAGE
@app.route("/")
def home():

    return render_template("index.html")


# WEBSITE ANALYSIS API
@app.route("/api/scan", methods=["POST"])
def scan_website():

    data = request.get_json(silent=True) or {}

    url = data.get("url", "").strip()

    # Validate URL
    parsed_url = urlparse(url)

    if parsed_url.scheme not in ("http", "https") or not parsed_url.hostname:

        return jsonify({
            "error": "Please enter a valid HTTP or HTTPS URL."
        }), 400

    try:

        # Run website scanner
        scan_results = analyze_website(url)

        if "Error" in scan_results:

            return jsonify(scan_results), 400

        # Calculate privacy score
        score_results = calculate_privacy_score(scan_results)

        if "Error" in score_results:

            return jsonify(score_results), 400

        # Combine results
        final_results = {
            "scan_results": scan_results,
            "score_results": score_results
        }

        return jsonify(final_results)

    except Exception as error:

        app.logger.exception("Website scanning failed")

        return jsonify({
            "error": "An unexpected error occurred during scanning."
        }), 500


# RUN APPLICATION
if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )