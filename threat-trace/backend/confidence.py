def calculate_confidence(
    threat_score,
    evidence,
    auth_data,
    url_data,
    ip_data
):
    """
    Calculate confidence in the forensic assessment.

    This is a heuristic confidence score, not a statistically
    calibrated probability.
    """

    score = 0.40

    evidence_count = len(evidence) if isinstance(evidence, list) else 0

    # More independent evidence increases confidence
    score += min(evidence_count * 0.05, 0.20)

    # Authentication evidence
    auth_failures = 0

    if isinstance(auth_data, dict):
        for key in ["spf", "dkim", "dmarc"]:
            value = str(auth_data.get(key, "")).lower()

            if value in ["fail", "softfail", "none"]:
                auth_failures += 1

    score += min(auth_failures * 0.05, 0.15)

    # Suspicious URLs
    suspicious_urls = 0

    if isinstance(url_data, dict):
        suspicious_urls = int(
            url_data.get("suspicious_url_count", 0) or 0
        )

    score += min(suspicious_urls * 0.05, 0.10)

    # Originating IP found
    origin_ip = ""

    if isinstance(ip_data, dict):
        origin_ip = ip_data.get("originating_ip", "")

    if origin_ip:
        score += 0.05

    # Extreme threat scores are easier to classify
    if threat_score >= 80 or threat_score <= 20:
        score += 0.05

    score = max(0.0, min(1.0, score))

    confidence_percent = round(score * 100)

    if confidence_percent >= 80:
        confidence_level = "HIGH"
    elif confidence_percent >= 60:
        confidence_level = "MEDIUM"
    else:
        confidence_level = "LOW"

    return {
        "confidence": confidence_percent,
        "confidence_level": confidence_level
    }


if __name__ == "__main__":
    result = calculate_confidence(
        98,
        [
            "SPF failed",
            "Suspicious credential URL",
            "Urgent password expiry"
        ],
        {
            "spf": "fail",
            "dkim": "none",
            "dmarc": "fail"
        },
        {
            "suspicious_url_count": 1
        },
        {
            "originating_ip": "91.240.118.82"
        }
    )

    print(result)