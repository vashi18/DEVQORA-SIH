"""
Threat-Trace Automated Test Runner

Runs all .eml files from:

tests/
├── legitimate/
├── phishing/
├── bec/
└── spoofed/

Each email is analyzed using the deterministic
forensic pipeline and compared with its expected label.
"""

from pathlib import Path

from parser import parse_email
from headers import analyze_authentication
from ip_extractor import analyze_received_chain
from url_analyzer import analyze_email_urls
from evidence_engine import calculate_evidence
from risk_engine import calculate_risk
from metrics import calculate_binary_metrics, calculate_multiclass_accuracy


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
TESTS_DIR = BASE_DIR / "tests"

LABELS = {
    "legitimate": "legitimate",
    "phishing": "phishing",
    "bec": "bec",
    "spoofed": "spoofed",
}


# ---------------------------------------------------------
# Analyze one email
# ---------------------------------------------------------

def analyze_test_email(file_path: Path, expected_label: str) -> dict:

    raw_email = file_path.read_text(
        encoding="utf-8",
        errors="replace"
    )

    # 1. Parse email
    email_data = parse_email(raw_email)

    # 2. Analyze authentication
    auth_data = analyze_authentication(email_data)

    # 3. Analyze Received headers / IP
    ip_data = analyze_received_chain(
        email_data.get("received", [])
    )

    # 4. Analyze URLs
    url_data = analyze_email_urls(
        email_data.get("body", "")
    )

    # 5. Deterministic evidence engine
    evidence_result = calculate_evidence(
        email_data=email_data,
        auth_data=auth_data,
        ip_data=ip_data,
        url_data=url_data,
    )

    # 6. Risk engine
    risk_result = calculate_risk(
        evidence_result["threat_score"]
    )

    predicted_label = evidence_result["classification"]

    return {
        "file": file_path.name,
        "expected": expected_label,
        "predicted": predicted_label,
        "score": evidence_result["threat_score"],
        "risk": risk_result["risk_level"],
        "correct": predicted_label == expected_label,
        "evidence": evidence_result.get("evidence", []),
    }


# ---------------------------------------------------------
# Find test emails
# ---------------------------------------------------------

def collect_test_files():

    test_files = []

    for label in LABELS:

        folder = TESTS_DIR / label

        if not folder.exists():
            print(f"WARNING: Missing folder: {folder}")
            continue

        for file_path in sorted(folder.glob("*.eml")):

            test_files.append(
                (file_path, label)
            )

    return test_files


# ---------------------------------------------------------
# Main test runner
# ---------------------------------------------------------

def main():

    print("\n" + "=" * 70)
    print("          THREAT-TRACE AUTOMATED TEST RUNNER")
    print("=" * 70)

    test_files = collect_test_files()

    if not test_files:
        print("\nNo .eml test files found.")
        print("Create your tests inside:")
        print(TESTS_DIR)
        return

    print(f"\nFound {len(test_files)} test email(s).\n")

    actual_labels = []
    predicted_labels = []

    results = []

    # -----------------------------------------------------
    # Run every email
    # -----------------------------------------------------

    for file_path, expected_label in test_files:

        try:

            result = analyze_test_email(
                file_path,
                expected_label
            )

            results.append(result)

            actual_labels.append(expected_label)
            predicted_labels.append(result["predicted"])

            status = "PASS" if result["correct"] else "FAIL"

            print(
                f"[{status}] "
                f"{file_path.parent.name}/{file_path.name}"
            )

            print(
                f"      Expected : {expected_label}"
            )

            print(
                f"      Predicted: {result['predicted']}"
            )

            print(
                f"      Score    : {result['score']}/100"
            )

            print(
                f"      Risk     : {result['risk']}"
            )

            print()

        except Exception as error:

            print(
                f"[ERROR] {file_path.name}: {error}"
            )

    # -----------------------------------------------------
    # Overall accuracy
    # -----------------------------------------------------

    correct = sum(
        result["correct"]
        for result in results
    )

    total = len(results)

    accuracy = (
        correct / total
        if total > 0
        else 0
    )

    print("=" * 70)
    print("                 OVERALL RESULTS")
    print("=" * 70)

    print(
        f"\nCorrect Predictions : {correct}/{total}"
    )

    print(
        f"Accuracy            : {accuracy * 100:.2f}%"
    )

    # -----------------------------------------------------
    # Multiclass accuracy
    # -----------------------------------------------------

    multiclass = calculate_multiclass_accuracy(
        actual_labels,
        predicted_labels
    )

    print("\nMulticlass Metrics")
    print("-" * 70)

    print(
        f"Accuracy : "
        f"{multiclass['accuracy'] * 100:.2f}%"
    )

    # -----------------------------------------------------
    # Binary malicious/legitimate metrics
    # -----------------------------------------------------

    binary_actual = [
        "malicious"
        if label != "legitimate"
        else "legitimate"
        for label in actual_labels
    ]

    binary_predicted = [
        "malicious"
        if label != "legitimate"
        else "legitimate"
        for label in predicted_labels
    ]

    binary = calculate_binary_metrics(
        binary_actual,
        binary_predicted,
        positive_label="malicious"
    )

    print("\nBinary Security Metrics")
    print("-" * 70)

    print(
        f"Accuracy            : "
        f"{binary['accuracy'] * 100:.2f}%"
    )

    print(
        f"Precision           : "
        f"{binary['precision'] * 100:.2f}%"
    )

    print(
        f"Recall              : "
        f"{binary['recall'] * 100:.2f}%"
    )

    print(
        f"F1 Score            : "
        f"{binary['f1_score'] * 100:.2f}%"
    )

    print(
        f"False Positive Rate : "
        f"{binary['false_positive_rate'] * 100:.2f}%"
    )

    print(
        f"False Negative Rate : "
        f"{binary['false_negative_rate'] * 100:.2f}%"
    )

    # -----------------------------------------------------
    # Summary
    # -----------------------------------------------------

    print("\n" + "=" * 70)
    print("                    TEST COMPLETE")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()