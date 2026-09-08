"""
Threat-Trace Explainability Engine

Converts technical forensic evidence into a human-readable
explanation for the SOC dashboard.
"""


def build_explanation(
    threat_score: int,
    classification: str,
    evidence: list,
    risk_level: str,
) -> dict:
    """
    Build a human-readable forensic explanation.
    """

    classification_names = {
        "legitimate": "Legitimate Email",
        "phishing": "Phishing Email",
        "bec": "Business Email Compromise (BEC)",
        "spoofed": "Spoofed Email",
    }

    title = classification_names.get(
        classification.lower(),
        "Suspicious Email"
    )

    if threat_score >= 80:
        severity = "Critical threat detected."
    elif threat_score >= 60:
        severity = "High-risk email detected."
    elif threat_score >= 30:
        severity = "Moderately suspicious email."
    else:
        severity = "No significant threat detected."

    evidence_items = []

    for item in evidence:
        evidence_items.append({
            "indicator": item,
            "severity": "high" if threat_score >= 70 else "medium"
        })

    if not evidence_items:
        evidence_items.append({
            "indicator": "No significant forensic indicators detected.",
            "severity": "low"
        })

    explanation = (
        f"{title}. {severity} "
        f"The deterministic forensic engine assigned a "
        f"threat score of {threat_score}/100."
    )

    return {
        "title": title,
        "risk_level": risk_level,
        "threat_score": threat_score,
        "severity_summary": severity,
        "explanation": explanation,
        "evidence": evidence_items,
        "evidence_count": len(evidence_items),
    }


# ---------------------------------------------------------
# Standalone test
# ---------------------------------------------------------

if __name__ == "__main__":

    test_evidence = [
        "SPF failed",
        "DKIM failed",
        "DMARC failed",
        "Typosquatting domain detected",
        "Artificial urgency detected",
        "Financial request detected",
        "Authority/impersonation language detected",
    ]

    result = build_explanation(
        threat_score=95,
        classification="bec",
        evidence=test_evidence,
        risk_level="CRITICAL",
    )

    print("\n===== THREAT-TRACE EXPLAINABILITY TEST =====\n")

    print("Title:")
    print(result["title"])

    print("\nRisk Level:")
    print(result["risk_level"])

    print("\nThreat Score:")
    print(result["threat_score"])

    print("\nExplanation:")
    print(result["explanation"])

    print("\nEvidence:")

    for item in result["evidence"]:
        print(f"  - {item['indicator']} [{item['severity']}]")

    print(f"\nEvidence Count: {result['evidence_count']}")