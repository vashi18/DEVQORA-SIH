"""
Threat-Trace Metrics Engine

Calculates:
- Accuracy
- Precision
- Recall
- F1 Score
- False Positive Rate
- False Negative Rate
"""


def safe_divide(a, b):
    """Avoid division-by-zero errors."""
    if b == 0:
        return 0.0
    return a / b


def calculate_binary_metrics(
    actual_labels: list,
    predicted_labels: list,
    positive_label: str = "malicious",
) -> dict:
    """
    Calculate binary classification metrics.

    positive_label represents a malicious/threat class.
    """

    if len(actual_labels) != len(predicted_labels):
        raise ValueError(
            "actual_labels and predicted_labels must have the same length."
        )

    true_positive = 0
    true_negative = 0
    false_positive = 0
    false_negative = 0

    for actual, predicted in zip(actual_labels, predicted_labels):

        actual_positive = actual == positive_label
        predicted_positive = predicted == positive_label

        if actual_positive and predicted_positive:
            true_positive += 1

        elif not actual_positive and not predicted_positive:
            true_negative += 1

        elif not actual_positive and predicted_positive:
            false_positive += 1

        elif actual_positive and not predicted_positive:
            false_negative += 1

    total = len(actual_labels)

    accuracy = safe_divide(
        true_positive + true_negative,
        total
    )

    precision = safe_divide(
        true_positive,
        true_positive + false_positive
    )

    recall = safe_divide(
        true_positive,
        true_positive + false_negative
    )

    f1_score = safe_divide(
        2 * precision * recall,
        precision + recall
    )

    false_positive_rate = safe_divide(
        false_positive,
        false_positive + true_negative
    )

    false_negative_rate = safe_divide(
        false_negative,
        false_negative + true_positive
    )

    return {
        "total_samples": total,

        "true_positive": true_positive,
        "true_negative": true_negative,
        "false_positive": false_positive,
        "false_negative": false_negative,

        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1_score, 4),

        "false_positive_rate": round(false_positive_rate, 4),
        "false_negative_rate": round(false_negative_rate, 4),
    }


def calculate_multiclass_accuracy(
    actual_labels: list,
    predicted_labels: list,
) -> dict:
    """
    Calculate overall accuracy for multiple Threat-Trace classes.
    """

    if len(actual_labels) != len(predicted_labels):
        raise ValueError(
            "actual_labels and predicted_labels must have the same length."
        )

    total = len(actual_labels)

    if total == 0:
        return {
            "total_samples": 0,
            "correct": 0,
            "incorrect": 0,
            "accuracy": 0.0,
        }

    correct = sum(
        actual == predicted
        for actual, predicted in zip(
            actual_labels,
            predicted_labels
        )
    )

    incorrect = total - correct

    return {
        "total_samples": total,
        "correct": correct,
        "incorrect": incorrect,
        "accuracy": round(correct / total, 4),
    }


# ---------------------------------------------------------
# Standalone test
# ---------------------------------------------------------

if __name__ == "__main__":

    actual = [
        "malicious",
        "malicious",
        "malicious",
        "legitimate",
        "legitimate",
        "legitimate",
        "malicious",
        "legitimate",
    ]

    predicted = [
        "malicious",
        "malicious",
        "legitimate",
        "legitimate",
        "legitimate",
        "malicious",
        "malicious",
        "legitimate",
    ]

    print("\n===== THREAT-TRACE METRICS TEST =====\n")

    binary_result = calculate_binary_metrics(
        actual,
        predicted,
        positive_label="malicious"
    )

    print("Binary Metrics:")
    print("-------------------------")
    print(f"Total Samples       : {binary_result['total_samples']}")
    print(f"True Positive       : {binary_result['true_positive']}")
    print(f"True Negative       : {binary_result['true_negative']}")
    print(f"False Positive      : {binary_result['false_positive']}")
    print(f"False Negative      : {binary_result['false_negative']}")
    print(f"Accuracy            : {binary_result['accuracy'] * 100:.2f}%")
    print(f"Precision           : {binary_result['precision'] * 100:.2f}%")
    print(f"Recall              : {binary_result['recall'] * 100:.2f}%")
    print(f"F1 Score            : {binary_result['f1_score'] * 100:.2f}%")
    print(
        f"False Positive Rate : "
        f"{binary_result['false_positive_rate'] * 100:.2f}%"
    )
    print(
        f"False Negative Rate : "
        f"{binary_result['false_negative_rate'] * 100:.2f}%"
    )

    multiclass_result = calculate_multiclass_accuracy(
        [
            "legitimate",
            "phishing",
            "bec",
            "spoofed",
            "legitimate",
        ],
        [
            "legitimate",
            "phishing",
            "bec",
            "phishing",
            "legitimate",
        ],
    )

    print("\nMulticlass Accuracy:")
    print("-------------------------")
    print(
        f"Accuracy : "
        f"{multiclass_result['accuracy'] * 100:.2f}%"
    )