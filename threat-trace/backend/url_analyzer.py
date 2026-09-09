"""
Threat-Trace URL Intelligence Engine

Analyzes URLs found inside email bodies and produces
explainable forensic indicators.

This is heuristic analysis only. It does not prove that
a URL is malicious.
"""

import ipaddress
import re
from urllib.parse import urlparse


# ============================================================
# CONFIGURATION
# ============================================================

URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"()\[\]{}]+",
    re.IGNORECASE
)

SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "password",
    "credential",
    "update",
    "confirm",
    "suspended",
    "unlock",
    "wallet",
    "payment",
    "invoice",
    "bank",
}

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "link",
    "work",
    "zip",
    "tk",
    "ml",
    "ga",
    "cf",
}

BRANDS = {
    "microsoft": [
        "microsoft.com",
        "office.com",
        "live.com",
    ],
    "google": [
        "google.com",
        "gmail.com",
    ],
    "apple": [
        "apple.com",
        "icloud.com",
    ],
    "amazon": [
        "amazon.com",
    ],
    "paypal": [
        "paypal.com",
    ],
}


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(text: str) -> list[str]:

    if not text:
        return []

    urls = URL_PATTERN.findall(text)

    cleaned = []

    for url in urls:

        # Remove common punctuation accidentally captured
        url = url.rstrip(".,;:!?")

        if url not in cleaned:
            cleaned.append(url)

    return cleaned


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def extract_domain(url: str) -> str:

    try:

        parsed = urlparse(url)

        return parsed.hostname.lower() if parsed.hostname else ""

    except Exception:

        return ""


# ============================================================
# IP ADDRESS DETECTION
# ============================================================

def is_ip_address(domain: str) -> bool:

    if not domain:
        return False

    try:

        ipaddress.ip_address(domain)

        return True

    except ValueError:

        return False


# ============================================================
# TYPOSQUATTING
# ============================================================

def detect_typosquatting(domain: str) -> list[str]:

    if not domain:
        return []

    indicators = []

    domain_lower = domain.lower()

    for brand, official_domains in BRANDS.items():

        # Brand exists in domain but domain isn't official
        if brand in domain_lower:

            is_official = any(
                domain_lower == official
                or domain_lower.endswith("." + official)
                for official in official_domains
            )

            if not is_official:

                indicators.append(
                    f"Possible {brand} typosquatting/impersonation"
                )

    # Common character substitutions
    typo_patterns = {
        "micros0ft": "Microsoft",
        "micr0soft": "Microsoft",
        "paypa1": "PayPal",
        "g00gle": "Google",
        "goog1e": "Google",
        "app1e": "Apple",
        "amaz0n": "Amazon",
    }

    for pattern, brand_name in typo_patterns.items():

        if pattern in domain_lower:

            indicators.append(
                f"Possible {brand_name} typosquatting"
            )

    return indicators


# ============================================================
# DOMAIN STRUCTURE ANALYSIS
# ============================================================

def analyze_domain_structure(
    domain: str
) -> tuple[int, list[str]]:

    risk = 0
    indicators = []

    if not domain:
        return risk, indicators

    # --------------------------------------------------------
    # IP address instead of domain
    # --------------------------------------------------------

    if is_ip_address(domain):

        risk += 30

        indicators.append(
            "URL uses an IP address instead of a domain name"
        )

    # --------------------------------------------------------
    # Punycode
    # --------------------------------------------------------

    if "xn--" in domain.lower():

        risk += 25

        indicators.append(
            "Domain uses Punycode, which may indicate IDN spoofing"
        )

    # --------------------------------------------------------
    # Excessive subdomains
    # --------------------------------------------------------

    parts = domain.split(".")

    if len(parts) >= 5:

        risk += 15

        indicators.append(
            "Domain contains an unusually large number of subdomains"
        )

    # --------------------------------------------------------
    # Multiple hyphens
    # --------------------------------------------------------

    if domain.count("-") >= 3:

        risk += 10

        indicators.append(
            "Domain contains multiple hyphens"
        )

    # --------------------------------------------------------
    # Suspicious TLD
    # --------------------------------------------------------

    if len(parts) >= 2:

        tld = parts[-1].lower()

        if tld in SUSPICIOUS_TLDS:

            risk += 15

            indicators.append(
                f"Domain uses a commonly abused TLD: .{tld}"
            )

    # --------------------------------------------------------
    # Brand impersonation
    # --------------------------------------------------------

    indicators.extend(
        detect_typosquatting(domain)
    )

    if detect_typosquatting(domain):

        risk += 25

    return risk, indicators


# ============================================================
# URL CONTENT ANALYSIS
# ============================================================

def analyze_url_content(
    url: str
) -> tuple[int, list[str]]:

    risk = 0
    indicators = []

    lower_url = url.lower()

    parsed = urlparse(url)

    # --------------------------------------------------------
    # HTTP
    # --------------------------------------------------------

    if parsed.scheme.lower() == "http":

        risk += 10

        indicators.append(
            "URL uses HTTP instead of HTTPS"
        )

    # --------------------------------------------------------
    # Credentials embedded in URL
    # --------------------------------------------------------

    if "@" in url:

        risk += 20

        indicators.append(
            "URL contains '@', which can hide the actual destination"
        )

    # --------------------------------------------------------
    # Excessive URL length
    # --------------------------------------------------------

    if len(url) > 150:

        risk += 10

        indicators.append(
            "URL is unusually long"
        )

    # --------------------------------------------------------
    # Percent encoding
    # --------------------------------------------------------

    if "%" in url:

        risk += 5

        indicators.append(
            "URL contains percent-encoded characters"
        )

    # --------------------------------------------------------
    # Suspicious words
    # --------------------------------------------------------

    found_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in lower_url:

            found_keywords.append(keyword)

    if found_keywords:

        risk += min(
            len(found_keywords) * 5,
            20
        )

        indicators.append(
            "Suspicious URL keywords: "
            + ", ".join(sorted(found_keywords))
        )

    return risk, indicators


# ============================================================
# SINGLE URL ANALYSIS
# ============================================================

def analyze_url(
    url: str,
    sender_domain: str = ""
) -> dict:

    domain = extract_domain(url)

    risk = 0
    indicators = []

    # Domain analysis
    domain_risk, domain_indicators = (
        analyze_domain_structure(domain)
    )

    risk += domain_risk
    indicators.extend(domain_indicators)

    # URL analysis
    url_risk, url_indicators = (
        analyze_url_content(url)
    )

    risk += url_risk
    indicators.extend(url_indicators)

    # --------------------------------------------------------
    # Sender-domain mismatch
    # --------------------------------------------------------

    if sender_domain and domain:

        sender_domain = sender_domain.lower().strip()

        if (
            domain != sender_domain
            and not domain.endswith(
                "." + sender_domain
            )
        ):

            # Only flag strongly when URL looks suspicious
            if risk >= 20:

                risk += 10

                indicators.append(
                    "Suspicious URL domain differs from sender domain"
                )

    # --------------------------------------------------------
    # Final score
    # --------------------------------------------------------

    risk = min(risk, 100)

    # --------------------------------------------------------
    # Severity
    # --------------------------------------------------------

    if risk >= 80:
        severity = "CRITICAL"

    elif risk >= 60:
        severity = "HIGH"

    elif risk >= 30:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    return {

        "url": url,

        "domain": domain,

        "risk_score": risk,

        "severity": severity,

        "suspicious": risk >= 30,

        "indicators": indicators,
    }


# ============================================================
# COMPLETE EMAIL URL ANALYSIS
# ============================================================

def analyze_email_urls(
    body: str,
    sender_domain: str = ""
) -> dict:

    urls = extract_urls(body)

    analyzed_urls = []

    suspicious_urls = []

    total_risk = 0

    for url in urls:

        result = analyze_url(
            url,
            sender_domain
        )

        analyzed_urls.append(result)

        total_risk += result["risk_score"]

        if result["suspicious"]:

            suspicious_urls.append(result)

    # --------------------------------------------------------
    # Overall URL risk
    # --------------------------------------------------------

    if not urls:

        overall_risk = 0

    else:

        overall_risk = min(
            total_risk,
            100
        )

    if overall_risk >= 80:
        overall_severity = "CRITICAL"

    elif overall_risk >= 60:
        overall_severity = "HIGH"

    elif overall_risk >= 30:
        overall_severity = "MEDIUM"

    else:
        overall_severity = "LOW"

    return {

        "url_count": len(urls),

        "suspicious_url_count":
            len(suspicious_urls),

        "risk_score":
            overall_risk,

        "severity":
            overall_severity,

        "urls":
            analyzed_urls,

        "suspicious_urls":
            suspicious_urls,
    }


# ============================================================
# LOCAL TEST
# ============================================================

if __name__ == "__main__":

    test_body = """
    Your Microsoft account requires verification.

    Click here:
    https://micros0ft-security-login.xyz/verify/account

    Another link:
    http://192.168.1.50/password

    Please login immediately.
    """

    result = analyze_email_urls(
        test_body,
        sender_domain="example-security.com"
    )

    print("\n")
    print("=" * 70)
    print("          THREAT-TRACE URL INTELLIGENCE")
    print("=" * 70)

    print(
        f"\nURLs found       : "
        f"{result['url_count']}"
    )

    print(
        f"Suspicious URLs  : "
        f"{result['suspicious_url_count']}"
    )

    print(
        f"Overall risk     : "
        f"{result['risk_score']}/100"
    )

    print(
        f"Severity         : "
        f"{result['severity']}"
    )

    print("\nURL DETAILS")
    print("-" * 70)

    for item in result["urls"]:

        print(
            f"\nURL: {item['url']}"
        )

        print(
            f"Domain: {item['domain']}"
        )

        print(
            f"Risk: {item['risk_score']}/100"
        )

        print(
            f"Severity: {item['severity']}"
        )

        if item["indicators"]:

            print("Indicators:")

            for indicator in item["indicators"]:

                print(
                    f"  - {indicator}"
                )

    print("\n")
    print("=" * 70)