"""
Threat-Trace Origin Trace Engine

Extracts and analyzes IP addresses from the email's
Received header chain.

Important:
The earliest public IP found in Received headers is treated
as the likely originating IP. It is NOT guaranteed to be the
true physical source because email headers can be forged.
"""

import ipaddress
import re


# ============================================================
# IP EXTRACTION
# ============================================================

IPV4_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

IPV6_PATTERN = re.compile(
    r"(?i)\b(?:"
    r"[0-9a-f]{1,4}:"
    r"){2,7}"
    r"[0-9a-f]{0,4}\b"
)


# ============================================================
# VALIDATE IP
# ============================================================

def is_valid_ip(ip: str) -> bool:

    try:
        ipaddress.ip_address(ip)
        return True

    except ValueError:
        return False


# ============================================================
# PUBLIC / PRIVATE CHECK
# ============================================================

def is_public_ip(ip: str) -> bool:

    try:

        address = ipaddress.ip_address(ip)

        return (
            not address.is_private
            and not address.is_loopback
            and not address.is_reserved
            and not address.is_link_local
            and not address.is_multicast
            and not address.is_unspecified
        )

    except ValueError:

        return False


# ============================================================
# EXTRACT IPs FROM ONE HEADER
# ============================================================

def extract_ips_from_header(
    received_header: str
) -> list[str]:

    if not received_header:
        return []

    candidates = []

    # IPv4
    candidates.extend(
        IPV4_PATTERN.findall(
            received_header
        )
    )

    # IPv6
    candidates.extend(
        IPV6_PATTERN.findall(
            received_header
        )
    )

    valid_ips = []

    for ip in candidates:

        if is_valid_ip(ip):

            if ip not in valid_ips:

                valid_ips.append(ip)

    return valid_ips


# ============================================================
# ANALYZE RECEIVED CHAIN
# ============================================================

def analyze_received_chain(
    received_headers: list[str]
) -> dict:

    if not received_headers:

        return {

            "header_count": 0,

            "all_ips": [],

            "public_ips": [],

            "private_or_non_public_ips": [],

            "originating_ip": None,

            "origin_confidence": "low",

            "origin_method": (
                "No Received headers available."
            ),

            "chain": [],
        }

    all_ips = []
    public_ips = []
    private_ips = []

    chain = []

    # --------------------------------------------------------
    # Analyze every Received header
    # --------------------------------------------------------

    for index, header in enumerate(
        received_headers
    ):

        header_ips = extract_ips_from_header(
            header
        )

        header_public_ips = []
        header_private_ips = []

        for ip in header_ips:

            if ip not in all_ips:

                all_ips.append(ip)

            if is_public_ip(ip):

                if ip not in public_ips:

                    public_ips.append(ip)

                if ip not in header_public_ips:

                    header_public_ips.append(ip)

            else:

                if ip not in private_ips:

                    private_ips.append(ip)

                if ip not in header_private_ips:

                    header_private_ips.append(ip)

        chain.append({

            "hop": index + 1,

            "ips": header_ips,

            "public_ips": header_public_ips,

            "private_or_non_public_ips":
                header_private_ips,

        })

    # --------------------------------------------------------
    # Received headers are normally newest -> oldest.
    #
    # Therefore scan from bottom to top.
    # --------------------------------------------------------

    originating_ip = None

    for header in reversed(
        received_headers
    ):

        header_ips = extract_ips_from_header(
            header
        )

        for ip in header_ips:

            if is_public_ip(ip):

                originating_ip = ip

                break

        if originating_ip:

            break

    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    if originating_ip:

        if len(received_headers) >= 2:

            origin_confidence = "high"

        else:

            origin_confidence = "medium"

        origin_method = (
            "Earliest public IP found by scanning "
            "the Received header chain from bottom to top."
        )

    else:

        origin_confidence = "low"

        origin_method = (
            "No public originating IP could be identified."
        )

    # --------------------------------------------------------
    # Return forensic result
    # --------------------------------------------------------

    return {

        "header_count": len(
            received_headers
        ),

        "all_ips": all_ips,

        "public_ips": public_ips,

        "private_or_non_public_ips":
            private_ips,

        "originating_ip": originating_ip,

        "origin_confidence":
            origin_confidence,

        "origin_method":
            origin_method,

        "chain": chain,
    }


# ============================================================
# FORENSIC SUMMARY
# ============================================================

def build_origin_summary(
    ip_data: dict
) -> dict:

    originating_ip = ip_data.get(
        "originating_ip"
    )

    public_ips = ip_data.get(
        "public_ips",
        []
    )

    private_ips = ip_data.get(
        "private_or_non_public_ips",
        []
    )

    header_count = ip_data.get(
        "header_count",
        0
    )

    confidence = ip_data.get(
        "origin_confidence",
        "low"
    )

    # --------------------------------------------------------
    # Human-readable summary
    # --------------------------------------------------------

    if originating_ip:

        summary = (
            f"The earliest public IP identified in the "
            f"Received header chain is {originating_ip}. "
            f"The analysis examined {header_count} "
            f"Received header(s)."
        )

    else:

        summary = (
            "No public originating IP could be reliably "
            "identified from the available Received headers."
        )

    return {

        "originating_ip": originating_ip,

        "confidence": confidence,

        "received_header_count":
            header_count,

        "public_ip_count":
            len(public_ips),

        "non_public_ip_count":
            len(private_ips),

        "summary": summary,

        "method":
            ip_data.get(
                "origin_method",
                ""
            ),
    }


# ============================================================
# COMPLETE ORIGIN ANALYSIS
# ============================================================

def analyze_origin(
    received_headers: list[str]
) -> dict:

    ip_data = analyze_received_chain(
        received_headers
    )

    summary = build_origin_summary(
        ip_data
    )

    return {

        **ip_data,

        "summary": summary,
    }


# ============================================================
# LOCAL TEST
# ============================================================

if __name__ == "__main__":

    test_received_headers = [

        "from mail.example.com "
        "(10.0.0.5) by mx.company.com",

        "from relay.example.net "
        "(192.168.1.10) by mail.example.com",

        "from attacker.example "
        "(185.220.101.5) by relay.example.net",
    ]

    result = analyze_origin(
        test_received_headers
    )

    print("\n")
    print("=" * 70)
    print("             THREAT-TRACE ORIGIN TRACE")
    print("=" * 70)

    print(
        f"\nReceived Headers : "
        f"{result['header_count']}"
    )

    print(
        f"All IPs          : "
        f"{result['all_ips']}"
    )

    print(
        f"Public IPs       : "
        f"{result['public_ips']}"
    )

    print(
        f"Private IPs      : "
        f"{result['private_or_non_public_ips']}"
    )

    print(
        f"\nOriginating IP   : "
        f"{result['originating_ip']}"
    )

    print(
        f"Confidence       : "
        f"{result['origin_confidence'].upper()}"
    )

    print(
        f"\nSummary:\n"
        f"{result['summary']['summary']}"
    )

    print("\n")
    print("RECEIVED CHAIN")
    print("-" * 70)

    for hop in result["chain"]:

        print(
            f"Hop {hop['hop']}: "
            f"{hop['ips']}"
        )

    print("\n")
    print("=" * 70)