import requests
from http.cookies import SimpleCookie
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin


# 1. THIRD-PARTY RESOURCE DETECTOR

def detect_trackers(response):

    soup = BeautifulSoup(response.text, "html.parser")

    website_domain = urlparse(response.url).hostname

    external_resources = []

    tags = {
        "script": "src",
        "img": "src",
        "iframe": "src",
        "link": "href",
        "source": "src",
        "video": "src",
        "audio": "src"
    }

    for tag, attribute in tags.items():

        elements = soup.find_all(tag)

        for element in elements:

            link = element.get(attribute)

            if not link:
                continue

            full_url = urljoin(response.url, link)

            domain = urlparse(full_url).hostname

            if domain and domain != website_domain:

                external_resources.append({
                    "Type": tag,
                    "URL": full_url,
                    "Domain": domain
                })

    return external_resources


# 2. HTTPS ANALYZER

def analyze_https(response):

    original_url = response.request.url
    final_url = response.url

    return {
        "Original URL": original_url,
        "Final URL": final_url,
        "HTTPS Enabled": final_url.startswith("https://"),
        "Redirected": bool(response.history),
        "Redirect Count": len(response.history)
    }


# 3. COOKIE SECURITY ANALYZER

def analyze_cookies(response):

    cookies = response.raw.headers.getlist("Set-Cookie")

    if not cookies:
        return {"message": "No cookies found"}

    results = {}

    for cookie_string in cookies:

        cookie = SimpleCookie()
        cookie.load(cookie_string)

        for name, morsel in cookie.items():

            results[name] = {
                "Secure": bool(morsel["secure"]),
                "HttpOnly": bool(morsel["httponly"]),
                "SameSite": morsel["samesite"] or "Not Set"
            }

    return results


# 4. MAIN WEBSITE ANALYZER

def analyze_website(url):

    try:

        parsed_url = urlparse(url)

        if parsed_url.scheme not in ("http", "https") or not parsed_url.hostname:
            return {"Error": "Enter a valid HTTP or HTTPS URL"}

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        headers = response.headers

        security_headers = {
            "Content-Security-Policy": "CSP",
            "Strict-Transport-Security": "HSTS",
            "X-Content-Type-Options": "Content Type Protection",
            "X-Frame-Options": "Clickjacking Protection",
            "Referrer-Policy": "Referrer Protection"
        }

        results = {}

        for header, description in security_headers.items():

            if header in headers:
                results[description] = "Present"

            else:
                results[description] = "Missing"

        cookie_results = analyze_cookies(response)

        https_results = analyze_https(response)

        tracker_results = detect_trackers(response)

        return {
            "Security Headers": results,
            "Cookie Analysis": cookie_results,
            "HTTPS Analysis": https_results,
            "Third Party Resources": tracker_results
        }

    except requests.exceptions.RequestException as e:

        return {"Error": str(e)}


# 5. PRIVACY SCORE GENERATOR

def calculate_privacy_score(scan_results):

    if "Error" in scan_results:
        return {"Error": scan_results["Error"]}

    score = 0
    possible_score = 0

    breakdown = {}

    # HTTPS SCORE: 30 POINTS

    https_data = scan_results.get("HTTPS Analysis", {})

    possible_score += 30

    if https_data.get("HTTPS Enabled") is True:

        score += 30
        breakdown["HTTPS"] = 30

    else:

        breakdown["HTTPS"] = 0

    # SECURITY HEADERS SCORE: 40 POINTS

    headers = scan_results.get("Security Headers", {})

    header_score = 0

    for name, status in headers.items():

        possible_score += 8

        if status == "Present":
            header_score += 8

    score += header_score

    breakdown["Security Headers"] = header_score

    # COOKIE SECURITY SCORE: 30 POINTS

    cookies = scan_results.get("Cookie Analysis", {})

    if cookies and "message" not in cookies:

        cookie_count = len(cookies)

        cookie_score = 0

        for name, attributes in cookies.items():

            attribute_score = 0

            if attributes["Secure"]:
                attribute_score += 1

            if attributes["HttpOnly"]:
                attribute_score += 1

            same_site = attributes["SameSite"].lower()

            if same_site in ("strict", "lax"):
                attribute_score += 1

            elif same_site == "none" and attributes["Secure"]:
                attribute_score += 1

            cookie_score += attribute_score

        average_cookie_score = cookie_score / (cookie_count * 3)

        cookie_points = round(average_cookie_score * 30)

        score += cookie_points
        possible_score += 30

        breakdown["Cookie Security"] = cookie_points

    else:

        breakdown["Cookie Security"] = "N/A"

    # FINAL SCORE

    if possible_score == 0:

        return {"Error": "No scan data available"}

    final_score = round((score / possible_score) * 100)

    return {
        "Privacy Score": final_score,
        "Breakdown": breakdown
    }

