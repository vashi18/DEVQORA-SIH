"""
Threat-Trace Risk Engine

Converts the deterministic evidence score produced by
evidence_engine.py into a risk level and risk metadata.
"""


def clamp_score(score: int) -> int:
    """Keep threat score between 0 and 100."""
    return max(0, min(100, int(score)))


def get_risk_level(score: int) -> str:
    """
    Convert a 0-100 threat score into a risk level.
    """

    score = clamp_score(score)

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    return "LOW"


def get_risk_color(level: str) -> str:
    """
    Return a UI-friendly color name for the dashboard.
    """

    colors = {
        "LOW": "green",
        "MEDIUM": "yellow",
        "HIGH": "orange",
        "CRITICAL": "red",
    }

    return colors.get(level, "gray")


def get_recommended_action(level: str) -> str:
    """
    Recommend what a SOC analyst should do.
    """

    actions = {
        "LOW": "Allow email and continue normal monitoring.",

        "MEDIUM": "Review the email and monitor for additional indicators.",

        "HIGH": "Quarantine the email and investigate the sender and indicators.",

        "CRITICAL": "Block or quarantine immediately and start forensic investigation.",
    }

    return actions.get(
        level,
        "Review the email manually."
    )


def calculate_risk(threat_score: int) -> dict:
    """
    Generate complete risk information from a threat score.
    """

    threat_score = clamp_score(threat_score)

    risk_level = get_risk_level(threat_score)

    return {
        "threat_score": threat_score,
        "risk_level": risk_level,
        "risk_color": get_risk_color(risk_level),
        "recommended_action": get_recommended_action(risk_level),
    }


# ---------------------------------------------------------
# Standalone test
# ---------------------------------------------------------

if __name__ == "__main__":

    test_scores = [5, 25, 45, 65, 85, 98]

    print("\n===== THREAT-TRACE RISK ENGINE TEST =====\n")

    for score in test_scores:

        result = calculate_risk(score)

        print(f"Threat Score : {result['threat_score']}")
        print(f"Risk Level   : {result['risk_level']}")
        print(f"Risk Color   : {result['risk_color']}")
        print(f"Action       : {result['recommended_action']}")
        print("-" * 50)