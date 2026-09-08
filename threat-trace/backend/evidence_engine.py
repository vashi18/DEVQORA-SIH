"""
Threat-Trace Evidence Engine

Deterministic forensic scoring engine.

Purpose:
- Analyze email authentication
- Analyze suspicious URLs
- Analyze social-engineering language
- Analyze sender/domain indicators
- Produce an explainable 0-100 threat score
- Produce evidence that explains every score contribution
"""

import re
from email.utils import parseaddr


# ============================================================
# HELPERS
# ============================================================

def clamp_score(score: int) -> int:
    return max(0, min(100, int(score)))


def contains_any(text: str, keywords: list[str]) -> bool:
    text = text.lower()

    return any(
        keyword.lower() in text
        for keyword in keywords
    )


def get_sender_domain(email_data: dict) -> str:

    sender = email_data.get("from", "")

    _, sender_email = parseaddr(sender)

    if "@" not in sender_email:
        return ""

    return sender_email.split("@", 1)[1].lower().strip()


# ============================================================
# AUTHENTICATION ANALYSIS
# ============================================================

def analyze_authentication(auth_data: dict) -> dict:

    score = 0
    evidence = []

    spf = str(
        auth_data.get("spf", "unknown")
    ).lower()

    dkim = str(
        auth_data.get("dkim", "unknown")
    ).lower()

    dmarc = str(
        auth_data.get("dmarc", "unknown")
    ).lower()

    dkim_aligned = auth_data.get(
        "dkim_aligned",
        True
    )

    # --------------------------------------------------------
    # SPF
    # --------------------------------------------------------

    if spf == "fail":

        score += 20

        evidence.append({
            "indicator": "SPF authentication failed",
            "category": "authentication",
            "score": 20,
            "severity": "high",
        })

    elif spf == "softfail":

        score += 10

        evidence.append({
            "indicator": "SPF authentication softfailed",
            "category": "authentication",
            "score": 10,
            "severity": "medium",
        })

    # --------------------------------------------------------
    # DKIM
    # --------------------------------------------------------

    if dkim == "fail":

        score += 15

        evidence.append({
            "indicator": "DKIM authentication failed",
            "category": "authentication",
            "score": 15,
            "severity": "high",
        })

    elif dkim == "none":

        score += 5

        evidence.append({
            "indicator": "DKIM signature not present",
            "category": "authentication",
            "score": 5,
            "severity": "medium",
        })

    # --------------------------------------------------------
    # DMARC
    # --------------------------------------------------------

    if dmarc == "fail":

        score += 20

        evidence.append({
            "indicator": "DMARC authentication failed",
            "category": "authentication",
            "score": 20,
            "severity": "high",
        })

    # --------------------------------------------------------
    # DKIM ALIGNMENT
    # --------------------------------------------------------

    if (
        auth_data.get("dkim_domain")
        and auth_data.get("from_domain")
        and not dkim_aligned
    ):

        score += 10

        evidence.append({
            "indicator": (
                "DKIM signing domain does not "
                "match sender domain"
            ),
            "category": "authentication",
            "score": 10,
            "severity": "high",
        })

    return {
        "score": score,
        "evidence": evidence,
    }


# ============================================================
# URL ANALYSIS
# ============================================================

def analyze_urls(url_data: dict) -> dict:

    score = 0
    evidence = []

    suspicious_count = int(
        url_data.get(
            "suspicious_url_count",
            0
        )
    )

    if suspicious_count > 0:

        url_score = min(
            suspicious_count * 15,
            30
        )

        score += url_score

        evidence.append({
            "indicator": (
                f"{suspicious_count} suspicious URL(s) detected"
            ),
            "category": "url",
            "score": url_score,
            "severity": "high",
        })

    return {
        "score": score,
        "evidence": evidence,
    }


# ============================================================
# CONTENT ANALYSIS
# ============================================================

def analyze_content(email_data: dict) -> dict:

    subject = str(
        email_data.get("subject", "")
    )

    body = str(
        email_data.get("body", "")
    )

    text = (
        subject +
        "\n" +
        body
    ).lower()

    score = 0
    evidence = []

    # --------------------------------------------------------
    # Urgency
    # --------------------------------------------------------

    urgency_words = [
        "urgent",
        "immediately",
        "immediate",
        "asap",
        "act now",
        "within 24 hours",
        "final warning",
        "expires today",
    ]

    if contains_any(
        text,
        urgency_words
    ):

        score += 10

        evidence.append({
            "indicator": "Artificial urgency detected",
            "category": "social_engineering",
            "score": 10,
            "severity": "medium",
        })

    # --------------------------------------------------------
    # Financial request
    # --------------------------------------------------------

    financial_words = [
        "wire transfer",
        "bank transfer",
        "transfer",
        "payment",
        "invoice",
        "bank account",
        "inr",
        "usd",
        "money",
    ]

    if contains_any(
        text,
        financial_words
    ):

        score += 20

        evidence.append({
            "indicator": "Financial transaction request detected",
            "category": "financial",
            "score": 20,
            "severity": "high",
        })

    # --------------------------------------------------------
    # Credential request
    # --------------------------------------------------------

    credential_words = [
        "password",
        "login",
        "log in",
        "verify your account",
        "account suspended",
        "account locked",
        "credential",
        "reset password",
    ]

    if contains_any(
        text,
        credential_words
    ):

        score += 20

        evidence.append({
            "indicator": "Credential/account verification language detected",
            "category": "credential",
            "score": 20,
            "severity": "high",
        })

    # --------------------------------------------------------
    # Authority / impersonation
    # --------------------------------------------------------

    authority_words = [
        "ceo",
        "cfo",
        "director",
        "administrator",
        "manager",
        "executive",
        "finance department",
        "security team",
        "it support",
    ]

    if contains_any(
        text,
        authority_words
    ):

        score += 15

        evidence.append({
            "indicator": "Authority/impersonation language detected",
            "category": "impersonation",
            "score": 15,
            "severity": "high",
        })

    # --------------------------------------------------------
    # Secrecy
    # --------------------------------------------------------

    secrecy_words = [
        "confidential",
        "keep this confidential",
        "do not tell anyone",
        "do not share",
        "secret",
    ]

    if contains_any(
        text,
        secrecy_words
    ):

        score += 10

        evidence.append({
            "indicator": "Secrecy/manipulation language detected",
            "category": "social_engineering",
            "score": 10,
            "severity": "medium",
        })

    return {
        "score": score,
        "evidence": evidence,
    }


# ============================================================
# SENDER / DOMAIN ANALYSIS
# ============================================================

def analyze_sender_domain(
    email_data: dict,
    url_data: dict
) -> dict:

    score = 0
    evidence = []

    sender_domain = get_sender_domain(
        email_data
    )

    suspicious_domains = [
        "micros0ft",
        "microsft",
        "microsofft",
        "paypa1",
        "paypai",
        "g00gle",
        "go0gle",
        "app1e",
        "amaz0n",
    ]

    # --------------------------------------------------------
    # Typosquatting
    # --------------------------------------------------------

    if contains_any(
        sender_domain,
        suspicious_domains
    ):

        score += 20

        evidence.append({
            "indicator": (
                "Possible brand typosquatting "
                "detected in sender domain"
            ),
            "category": "domain",
            "score": 20,
            "severity": "high",
        })

    # --------------------------------------------------------
    # Suspicious security/account domain
    # --------------------------------------------------------

    suspicious_terms = [
        "security",
        "verify",
        "verification",
        "login",
        "account",
        "secure",
        "support",
    ]

    if contains_any(
        sender_domain,
        suspicious_terms
    ):

        score += 5

        evidence.append({
            "indicator": (
                "Sender domain contains "
                "security/account-related terms"
            ),
            "category": "domain",
            "score": 5,
            "severity": "medium",
        })

    # --------------------------------------------------------
    # URL domain mismatch
    # --------------------------------------------------------

    suspicious_urls = url_data.get(
        "suspicious_urls",
        []
    )

    if suspicious_urls:

        for item in suspicious_urls:

            url_domain = str(
                item.get("domain", "")
            ).lower()

            if (
                url_domain
                and sender_domain
                and url_domain != sender_domain
            ):

                score += 5

                evidence.append({
                    "indicator": (
                        "Email contains a URL hosted "
                        "on a different domain than the sender"
                    ),
                    "category": "domain",
                    "score": 5,
                    "severity": "medium",
                })

                break

    return {
        "score": score,
        "evidence": evidence,
    }


# ============================================================
# CLASSIFICATION
# ============================================================

def classify_threat(
    score: int,
    email_data: dict,
    auth_data: dict,
    url_data: dict,
    content_result: dict,
    sender_result: dict,
) -> str:

    text = (
        str(email_data.get("subject", "")) +
        "\n" +
        str(email_data.get("body", ""))
    ).lower()

    financial = contains_any(
        text,
        [
            "wire transfer",
            "bank transfer",
            "payment",
            "invoice",
            "bank account",
            "inr",
            "usd",
        ]
    )

    authority = contains_any(
        text,
        [
            "ceo",
            "cfo",
            "director",
            "manager",
            "executive",
        ]
    )

    credential = contains_any(
        text,
        [
            "password",
            "login",
            "verify your account",
            "account suspended",
            "credential",
        ]
    )

    suspicious_urls = (
        url_data.get(
            "suspicious_url_count",
            0
        ) > 0
    )

    authentication_failed = (
        auth_data.get("spf") in [
            "fail",
            "softfail"
        ]
        or
        auth_data.get("dkim") == "fail"
        or
        auth_data.get("dmarc") == "fail"
    )

    # BEC
    if (
        financial
        and authority
        and authentication_failed
    ):
        return "bec"

    # Phishing
    if (
        credential
        and suspicious_urls
    ):
        return "phishing"

    if (
        credential
        and authentication_failed
    ):
        return "phishing"

    # Spoofed
    if (
        authentication_failed
        and score >= 50
    ):
        return "spoofed"

    # Legitimate
    if score < 30:
        return "legitimate"

    return "phishing"


# ============================================================
# MAIN EVIDENCE CALCULATION
# ============================================================

def calculate_evidence(
    email_data: dict,
    auth_data: dict,
    ip_data: dict,
    url_data: dict,
) -> dict:

    # --------------------------------------------------------
    # Individual evidence engines
    # --------------------------------------------------------

    authentication = analyze_authentication(
        auth_data
    )

    urls = analyze_urls(
        url_data
    )

    content = analyze_content(
        email_data
    )

    sender = analyze_sender_domain(
        email_data,
        url_data
    )

    # --------------------------------------------------------
    # Combine scores
    # --------------------------------------------------------

    authentication_score = authentication["score"]
    url_score = urls["score"]
    content_score = content["score"]
    sender_score = sender["score"]

    raw_score = (
        authentication_score
        + url_score
        + content_score
        + sender_score
    )

    threat_score = clamp_score(
        raw_score
    )

    # --------------------------------------------------------
    # Combine evidence
    # --------------------------------------------------------

    evidence_objects = (
        authentication["evidence"]
        + urls["evidence"]
        + content["evidence"]
        + sender["evidence"]
    )

    # Simple evidence strings for existing modules
    evidence_list = [
        item["indicator"]
        for item in evidence_objects
    ]

    # --------------------------------------------------------
    # Classification
    # --------------------------------------------------------

    classification = classify_threat(
        score=threat_score,
        email_data=email_data,
        auth_data=auth_data,
        url_data=url_data,
        content_result=content,
        sender_result=sender,
    )

    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    if len(evidence_objects) >= 6:
        confidence = 0.95

    elif len(evidence_objects) >= 4:
        confidence = 0.90

    elif len(evidence_objects) >= 2:
        confidence = 0.80

    elif len(evidence_objects) == 1:
        confidence = 0.65

    else:
        confidence = 0.55

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    return {

        "threat_score": threat_score,

        "classification": classification,

        "confidence": confidence,

        # Human-readable evidence
        "evidence": evidence_list,

        # Detailed evidence for dashboard
        "evidence_details": evidence_objects,

        # Score breakdown
        "risk_breakdown": {

            "authentication": authentication_score,

            "urls": url_score,

            "content": content_score,

            "sender_domain": sender_score,

            "total_before_cap": raw_score,

            "final_score": threat_score,
        },

        # Detailed forensic data
        "details": {

            "authentication": authentication,

            "urls": urls,

            "content": content,

            "sender_domain": sender,

            "originating_ip": ip_data.get(
                "originating_ip"
            ),

            "ip_confidence": ip_data.get(
                "origin_confidence"
            ),
        },
    }


# ============================================================
# BACKWARD-COMPATIBLE WRAPPER
# ============================================================

def calculate_risk(
    email_data: dict,
    auth_data: dict,
    ip_data: dict,
    url_data: dict,
) -> dict:

    return calculate_evidence(
        email_data=email_data,
        auth_data=auth_data,
        ip_data=ip_data,
        url_data=url_data,
    )


# ============================================================
# LOCAL TEST
# ============================================================

if __name__ == "__main__":

    test_email = {

        "from": (
            "CEO <ceo@micros0ft-finance.com>"
        ),

        "to": "finance@company.com",

        "subject": "URGENT WIRE TRANSFER",

        "body": """
        Please immediately transfer INR 48,50,000
        to the attached bank account.

        This is confidential.
        Do not tell anyone.
        """,
    }

    test_auth = {

        "spf": "fail",

        "dkim": "fail",

        "dmarc": "fail",

        "dkim_domain": "",

        "from_domain": "micros0ft-finance.com",

    }

    test_ip = {

        "originating_ip": "185.220.101.5",

        "origin_confidence": "high",

    }

    test_urls = {

        "url_count": 0,

        "suspicious_url_count": 0,

        "suspicious_urls": [],

    }

    result = calculate_evidence(
        email_data=test_email,
        auth_data=test_auth,
        ip_data=test_ip,
        url_data=test_urls,
    )

    print("\n")
    print("=" * 65)
    print("          THREAT-TRACE EVIDENCE ENGINE")
    print("=" * 65)

    print(
        f"\nThreat Score: "
        f"{result['threat_score']}/100"
    )

    print(
        f"Classification: "
        f"{result['classification'].upper()}"
    )

    print(
        f"Confidence: "
        f"{result['confidence'] * 100:.0f}%"
    )

    print("\n")
    print("RISK BREAKDOWN")
    print("-" * 65)

    for key, value in result[
        "risk_breakdown"
    ].items():

        print(
            f"{key:25} : {value}"
        )

    print("\n")
    print("FORENSIC EVIDENCE")
    print("-" * 65)

    for item in result[
        "evidence_details"
    ]:

        print(
            f"[+{item['score']:02}] "
            f"{item['indicator']}"
        )

    print("\n")
    print("=" * 65)