import re
from email.utils import parseaddr


def analyze_authentication(parsed_email: dict) -> dict:
    """
    Analyze SPF, DKIM and DMARC authentication results
    from a parsed email.
    """

    # --------------------------------
    # Sender information
    # --------------------------------

    from_header = parsed_email.get("from", "")

    sender_name, sender_email = parseaddr(from_header)

    sender_domain = ""

    if "@" in sender_email:
        sender_domain = sender_email.split("@", 1)[1].lower().strip()

    # --------------------------------
    # Get authentication headers
    # --------------------------------

    authentication_results = parsed_email.get(
        "authentication_results",
        []
    )

    received_spf = parsed_email.get(
        "received_spf",
        []
    )

    dkim_signatures = parsed_email.get(
        "dkim_signature",
        []
    )

    # Convert headers to strings
    auth_text = " ".join(
        str(value) for value in authentication_results
    ).lower()

    spf_text = " ".join(
        str(value) for value in received_spf
    ).lower()

    dkim_text = " ".join(
        str(value) for value in dkim_signatures
    ).lower()

    # --------------------------------
    # SPF
    # --------------------------------

    spf = "unknown"

    match = re.search(
        r"\bspf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)",
        auth_text
    )

    if match:
        spf = match.group(1)

    else:
        # Try Received-SPF header
        match = re.search(
            r"\b(pass|fail|softfail|neutral|none|temperror|permerror)\b",
            spf_text
        )

        if match:
            spf = match.group(1)

    # --------------------------------
    # DKIM
    # --------------------------------

    dkim = "unknown"

    match = re.search(
        r"\bdkim\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)",
        auth_text
    )

    if match:
        dkim = match.group(1)

    # --------------------------------
    # DMARC
    # --------------------------------

    dmarc = "unknown"

    match = re.search(
        r"\bdmarc\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)",
        auth_text
    )

    if match:
        dmarc = match.group(1)

    # --------------------------------
    # DKIM signing domain
    # --------------------------------

    dkim_domain = ""

    match = re.search(
        r"(?:^|[\s;])d=([^;\s]+)",
        dkim_text,
        re.IGNORECASE
    )

    if match:
        dkim_domain = match.group(1).strip().lower()

    # --------------------------------
    # DKIM domain alignment
    # --------------------------------

    dkim_aligned = False

    if sender_domain and dkim_domain:
        dkim_aligned = (
            sender_domain == dkim_domain
        )

    # --------------------------------
    # Authentication risk
    # --------------------------------

    authentication_risk = 0

    findings = []

    # SPF
    if spf == "fail":

        authentication_risk += 30

        findings.append(
            "SPF failed"
        )

    elif spf == "softfail":

        authentication_risk += 15

        findings.append(
            "SPF softfail"
        )

    elif spf == "pass":

        findings.append(
            "SPF passed"
        )

    elif spf == "none":

        findings.append(
            "SPF returned none"
        )

    else:

        findings.append(
            "SPF result unavailable"
        )

    # DKIM
    if dkim == "fail":

        authentication_risk += 25

        findings.append(
            "DKIM failed"
        )

    elif dkim == "none":

        authentication_risk += 10

        findings.append(
            "DKIM not present"
        )

    elif dkim == "pass":

        findings.append(
            "DKIM passed"
        )

    else:

        findings.append(
            "DKIM result unavailable"
        )

    # DMARC
    if dmarc == "fail":

        authentication_risk += 30

        findings.append(
            "DMARC failed"
        )

    elif dmarc == "pass":

        findings.append(
            "DMARC passed"
        )

    elif dmarc == "none":

        findings.append(
            "DMARC returned none"
        )

    else:

        findings.append(
            "DMARC result unavailable"
        )

    # --------------------------------
    # DKIM alignment
    # --------------------------------

    if (
        dkim_domain
        and sender_domain
        and not dkim_aligned
    ):

        authentication_risk += 15

        findings.append(
            "DKIM signing domain does not match sender domain"
        )

    # Keep risk between 0 and 100
    authentication_risk = min(
        authentication_risk,
        100
    )

    # --------------------------------
    # Return result
    # --------------------------------

    return {

        "from_domain": sender_domain,

        "sender_name": sender_name,

        "sender_email": sender_email,

        "spf": spf,

        "dkim": dkim,

        "dmarc": dmarc,

        "dkim_domain": dkim_domain,

        "dkim_aligned": dkim_aligned,

        "authentication_risk": authentication_risk,

        "findings": findings,

        "raw_authentication_results":
            authentication_results
    }


# --------------------------------
# Compatibility function
# --------------------------------

def extract_headers(parsed_email: dict) -> dict:
    """
    Compatibility wrapper.

    Allows code using extract_headers()
    to work with the same authentication analyzer.
    """

    return analyze_authentication(parsed_email)