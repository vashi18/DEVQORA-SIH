"""
Threat-Trace Case Manager

Creates:
1. Unique forensic Case ID
2. SHA-256 hash of the original email
3. SHA-256 hash of the complete forensic evidence

The hashes allow investigators to verify that evidence
has not changed after analysis.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone


# ============================================================
# CASE ID
# ============================================================

def generate_case_id() -> str:
    """
    Generate a unique forensic case identifier.

    Example:
    TT-20260908-A1B2C3D4
    """

    date_part = datetime.now(
        timezone.utc
    ).strftime("%Y%m%d")

    unique_part = uuid.uuid4().hex[:8].upper()

    return f"TT-{date_part}-{unique_part}"


# ============================================================
# SHA-256
# ============================================================

def calculate_sha256(data) -> str:
    """
    Calculate SHA-256 hash.

    Supports:
    - str
    - bytes
    - dictionaries/lists
    """

    if isinstance(data, bytes):

        raw_data = data

    elif isinstance(data, str):

        raw_data = data.encode(
            "utf-8",
            errors="replace"
        )

    else:

        serialized = json.dumps(
            data,
            sort_keys=True,
            ensure_ascii=False,
            default=str
        )

        raw_data = serialized.encode(
            "utf-8"
        )

    return hashlib.sha256(
        raw_data
    ).hexdigest()


# ============================================================
# EMAIL HASH
# ============================================================

def calculate_email_hash(
    raw_email: str
) -> str:

    return calculate_sha256(
        raw_email
    )


# ============================================================
# EVIDENCE HASH
# ============================================================

def calculate_evidence_hash(
    evidence: dict
) -> str:

    return calculate_sha256(
        evidence
    )


# ============================================================
# CASE CREATION
# ============================================================

def create_case(
    raw_email: str,
    evidence: dict
) -> dict:

    case_id = generate_case_id()

    email_hash = calculate_email_hash(
        raw_email
    )

    evidence_hash = calculate_evidence_hash(
        evidence
    )

    created_at = datetime.now(
        timezone.utc
    ).isoformat()

    return {

        "case_id": case_id,

        "created_at": created_at,

        "evidence_integrity": {

            "original_email_sha256":
                email_hash,

            "forensic_evidence_sha256":
                evidence_hash,

            "algorithm":
                "SHA-256",
        },

    }


# ============================================================
# VERIFY HASH
# ============================================================

def verify_sha256(
    data,
    expected_hash: str
) -> bool:

    actual_hash = calculate_sha256(
        data
    )

    return actual_hash.lower() == (
        expected_hash.lower()
    )


# ============================================================
# LOCAL TEST
# ============================================================

if __name__ == "__main__":

    sample_email = """
From: attacker@example.com
To: victim@company.com
Subject: Urgent verification

Please verify your account immediately.
"""

    sample_evidence = {

        "threat_score": 94,

        "classification": "bec",

        "originating_ip":
            "185.220.101.5",

        "indicators_of_compromise": [

            "SPF failed",

            "DMARC failed",

            "Possible Microsoft typosquatting",

        ],
    }

    case = create_case(
        sample_email,
        sample_evidence
    )

    print("\n")
    print("=" * 70)
    print("             THREAT-TRACE CASE MANAGER")
    print("=" * 70)

    print(
        f"\nCase ID:\n"
        f"{case['case_id']}"
    )

    print(
        f"\nCreated:\n"
        f"{case['created_at']}"
    )

    print(
        "\nOriginal Email SHA-256:\n"
        f"{case['evidence_integrity']['original_email_sha256']}"
    )

    print(
        "\nForensic Evidence SHA-256:\n"
        f"{case['evidence_integrity']['forensic_evidence_sha256']}"
    )

    print(
        "\nAlgorithm:\n"
        f"{case['evidence_integrity']['algorithm']}"
    )

    print("\n")
    print("=" * 70)