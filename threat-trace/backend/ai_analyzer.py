"""
Threat-Trace AI Analyzer

Uses Gemini for behavioral email analysis.

If Gemini is unavailable, a deterministic fallback is used so
the forensic pipeline can still return a result.
"""

import os
import re
import time

from dotenv import load_dotenv
from pydantic import BaseModel, Field
from google import genai


# ============================================================
# ENVIRONMENT
# ============================================================

load_dotenv()


# ============================================================
# AI RESPONSE SCHEMA
# ============================================================

class AIAnalysisResult(BaseModel):

    threat_score: int = Field(
        ge=0,
        le=100
    )

    classification: str

    psychological_tactic: str

    originating_ip: str | None = None

    forensic_summary: str

    indicators_of_compromise: list[str] = Field(
        default_factory=list
    )


# ============================================================
# GEMINI CLIENT
# ============================================================

def get_gemini_client():

    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        return None

    return genai.Client(
        api_key=api_key
    )


# ============================================================
# TEXT HELPERS
# ============================================================

def contains_any(text: str, keywords: list[str]) -> bool:

    text = text.lower()

    return any(
        keyword.lower() in text
        for keyword in keywords
    )


# ============================================================
# DETERMINISTIC FALLBACK
# ============================================================

def fallback_analysis(
    email_data: dict,
    auth_data: dict,
    ip_data: dict,
    url_data: dict,
) -> dict:

    subject = str(
        email_data.get("subject", "")
    )

    body = str(
        email_data.get("body", "")
    )

    sender = str(
        email_data.get("from", "")
    )

    full_text = (
        subject + "\n" +
        body + "\n" +
        sender
    ).lower()

    score = 0

    indicators = []

    # --------------------------------------------------------
    # Authentication
    # --------------------------------------------------------

    spf = str(
        auth_data.get("spf", "")
    ).lower()

    dkim = str(
        auth_data.get("dkim", "")
    ).lower()

    dmarc = str(
        auth_data.get("dmarc", "")
    ).lower()

    if spf == "fail":
        score += 25
        indicators.append("SPF authentication failed.")

    elif spf == "softfail":
        score += 15
        indicators.append("SPF authentication softfailed.")

    if dkim == "fail":
        score += 20
        indicators.append("DKIM authentication failed.")

    elif dkim == "none":
        score += 10
        indicators.append("DKIM signature is missing.")

    if dmarc == "fail":
        score += 25
        indicators.append("DMARC authentication failed.")

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
        "expires today",
        "final warning",
    ]

    if contains_any(full_text, urgency_words):

        score += 10

        indicators.append(
            "Urgency-based language detected."
        )

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
        "amount",
    ]

    financial_request = contains_any(
        full_text,
        financial_words
    )

    if financial_request:

        score += 20

        indicators.append(
            "Financial transaction language detected."
        )

    # --------------------------------------------------------
    # Credential harvesting
    # --------------------------------------------------------

    credential_words = [
        "password",
        "login",
        "log in",
        "verify your account",
        "account suspended",
        "account locked",
        "credential",
        "security verification",
        "reset password",
    ]

    credential_request = contains_any(
        full_text,
        credential_words
    )

    if credential_request:

        score += 20

        indicators.append(
            "Credential or account verification language detected."
        )

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

    authority_language = contains_any(
        full_text,
        authority_words
    )

    if authority_language:

        score += 15

        indicators.append(
            "Authority or impersonation language detected."
        )

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    suspicious_url_count = url_data.get(
        "suspicious_url_count",
        0
    )

    url_count = url_data.get(
        "url_count",
        0
    )

    if suspicious_url_count > 0:

        score += min(
            suspicious_url_count * 20,
            30
        )

        indicators.append(
            f"{suspicious_url_count} suspicious URL(s) detected."
        )

    elif url_count > 0:

        indicators.append(
            f"{url_count} URL(s) detected."
        )

    # --------------------------------------------------------
    # Origin IP
    # --------------------------------------------------------

    originating_ip = ip_data.get(
        "originating_ip"
    )

    # IP presence itself is NOT treated as malicious.
    if originating_ip:

        indicators.append(
            f"Originating public IP identified: {originating_ip}"
        )

    # --------------------------------------------------------
    # Classification
    # --------------------------------------------------------

    score = min(
        max(score, 0),
        100
    )

    authentication_failed = (
        spf == "fail"
        or dkim == "fail"
        or dmarc == "fail"
        or spf == "softfail"
    )

    # BEC
    if (
        financial_request
        and authority_language
        and authentication_failed
    ):

        classification = "bec"

        psychological_tactic = (
            "False urgency and authority bias"
        )

    # Phishing
    elif (
        credential_request
        and suspicious_url_count > 0
    ):

        classification = "phishing"

        psychological_tactic = (
            "Fear and loss aversion"
        )

    elif (
        credential_request
        and authentication_failed
    ):

        classification = "phishing"

        psychological_tactic = (
            "Fear and account-loss pressure"
        )

    # Spoofed
    elif authentication_failed and score >= 50:

        classification = "spoofed"

        psychological_tactic = (
            "Impersonation and trust exploitation"
        )

    # Legitimate
    elif score < 30:

        classification = "legitimate"

        psychological_tactic = (
            "No significant psychological manipulation detected"
        )

    else:

        classification = "phishing"

        psychological_tactic = (
            "Suspicion-inducing social engineering"
        )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    if classification == "legitimate":

        summary = (
            "The email shows no strong combination of "
            "authentication, content, or URL indicators "
            "associated with malicious activity."
        )

    elif classification == "bec":

        summary = (
            "The email contains indicators consistent with "
            "business email compromise, including financial "
            "request language, authority impersonation, "
            "urgency, and authentication failures."
        )

    elif classification == "phishing":

        summary = (
            "The email contains indicators consistent with "
            "phishing or credential harvesting."
        )

    else:

        summary = (
            "The email contains authentication or "
            "impersonation indicators consistent with "
            "a potentially spoofed message."
        )

    return {

        "threat_score": score,

        "classification": classification,

        "psychological_tactic": psychological_tactic,

        "originating_ip": originating_ip,

        "forensic_summary": summary,

        "indicators_of_compromise": indicators,

        "ai_status": "fallback",

        "ai_message": (
            "Gemini AI was unavailable. "
            "Threat-Trace deterministic fallback analysis "
            "was used."
        ),
    }


# ============================================================
# GEMINI AI ANALYSIS
# ============================================================

def analyze_email_with_ai(
    email_data: dict,
    auth_data: dict,
    ip_data: dict,
    url_data: dict,
) -> dict:

    client = get_gemini_client()

    # --------------------------------------------------------
    # No API key -> fallback
    # --------------------------------------------------------

    if client is None:

        return fallback_analysis(
            email_data,
            auth_data,
            ip_data,
            url_data,
        )

    # --------------------------------------------------------
    # Prepare forensic information
    # --------------------------------------------------------

    prompt = f"""
You are the AI behavioral analysis engine for Threat-Trace,
an automated email forensic and threat intelligence platform.

Analyze the supplied email using BOTH:
1. Email content
2. RFC/header forensic information

Do not invent facts.

Classify the email as exactly one of:

- legitimate
- phishing
- bec
- spoofed

Threat score:
0 = completely benign
100 = extremely malicious

Consider:

- SPF
- DKIM
- DMARC
- sender domain
- originating IP
- suspicious URLs
- credential requests
- financial requests
- urgency
- authority impersonation
- social engineering
- psychological manipulation
- possible indicators of compromise

EMAIL
--------------------------------------------------

From:
{email_data.get("from", "")}

To:
{email_data.get("to", "")}

Subject:
{email_data.get("subject", "")}

Date:
{email_data.get("date", "")}

Body:
{email_data.get("body", "")[:12000]}


AUTHENTICATION
--------------------------------------------------

SPF:
{auth_data.get("spf", "unknown")}

DKIM:
{auth_data.get("dkim", "unknown")}

DMARC:
{auth_data.get("dmarc", "unknown")}

DKIM Domain:
{auth_data.get("dkim_domain", "")}

Sender Domain:
{auth_data.get("from_domain", "")}


IP FORENSICS
--------------------------------------------------

Originating IP:
{ip_data.get("originating_ip")}

All Public IPs:
{ip_data.get("public_ips", [])}


URL FORENSICS
--------------------------------------------------

URL Count:
{url_data.get("url_count", 0)}

Suspicious URL Count:
{url_data.get("suspicious_url_count", 0)}

URLs:
{url_data.get("urls", [])}

Suspicious URLs:
{url_data.get("suspicious_urls", [])}


Return ONLY structured JSON matching the requested schema.
"""

    # --------------------------------------------------------
    # Retry configuration
    # --------------------------------------------------------

    max_attempts = 3

    for attempt in range(max_attempts):

        try:

            response = client.models.generate_content(

                model="gemini-3.8-flash",

                contents=prompt,

                config={
                    "response_mime_type": "application/json",

                    "response_schema": AIAnalysisResult,

                    "temperature": 0.1,
                },
            )

            # ------------------------------------------------
            # Parse structured response
            # ------------------------------------------------

            result = response.parsed

            if result is None:

                raise ValueError(
                    "Gemini returned no structured response."
                )

            if isinstance(result, AIAnalysisResult):

                output = result.model_dump()

            elif isinstance(result, dict):

                output = result

            else:

                output = AIAnalysisResult.model_validate(
                    result
                ).model_dump()

            # ------------------------------------------------
            # Add status
            # ------------------------------------------------

            output["ai_status"] = "success"

            return output

        except Exception as error:

            error_text = str(error).lower()

            transient_error = any(
                phrase in error_text
                for phrase in [
                    "429",
                    "resource exhausted",
                    "503",
                    "unavailable",
                    "high demand",
                    "overloaded",
                    "temporarily",
                    "timeout",
                    "deadline",
                ]
            )

            # Retry only transient errors
            if transient_error and attempt < max_attempts - 1:

                wait_time = 2 ** attempt

                time.sleep(
                    wait_time
                )

                continue

            # ------------------------------------------------
            # Gemini failed -> deterministic fallback
            # ------------------------------------------------

            fallback = fallback_analysis(
                email_data,
                auth_data,
                ip_data,
                url_data,
            )

            fallback["ai_message"] = (
                "Gemini AI analysis failed. "
                "Threat-Trace deterministic fallback analysis "
                f"was used. Error: {str(error)[:300]}"
            )

            return fallback

    # --------------------------------------------------------
    # Safety fallback
    # --------------------------------------------------------

    return fallback_analysis(
        email_data,
        auth_data,
        ip_data,
        url_data,
    )


# ============================================================
# LOCAL TEST
# ============================================================

if __name__ == "__main__":

    test_email = {

        "from": "CEO <ceo@micros0ft-finance.com>",

        "to": "finance@company.com",

        "subject": "URGENT WIRE TRANSFER",

        "date": "Tue, 08 Sep 2026 10:00:00 +0000",

        "body": """
        Please immediately transfer INR 48,50,000
        to the attached bank account.
        This is confidential.
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

        "public_ips": [
            "185.220.101.5"
        ],
    }

    test_url = {

        "url_count": 0,

        "suspicious_url_count": 0,

        "urls": [],

        "suspicious_urls": [],
    }

    result = fallback_analysis(
        test_email,
        test_auth,
        test_ip,
        test_url,
    )

    print("\n" + "=" * 60)
    print("       THREAT-TRACE AI ANALYZER TEST")
    print("=" * 60)

    print("\nThreat Score:")
    print(result["threat_score"])

    print("\nClassification:")
    print(result["classification"])

    print("\nPsychological Tactic:")
    print(result["psychological_tactic"])

    print("\nOriginating IP:")
    print(result["originating_ip"])

    print("\nForensic Summary:")
    print(result["forensic_summary"])

    print("\nIndicators:")

    for indicator in result["indicators_of_compromise"]:
        print(f"  - {indicator}")

    print("\nAI Status:")
    print(result["ai_status"])