from pathlib import Path


# =========================================================
# THREAT-TRACE EMAIL STORAGE
# =========================================================

BASE_DIR = Path(__file__).resolve().parent

EMAILS_DIR = BASE_DIR / "emails"

ACTUAL_DIR = EMAILS_DIR / "actual"
SPAM_DIR = EMAILS_DIR / "spam"


def create_email_folders():
    """Create the actual and spam email storage folders."""

    ACTUAL_DIR.mkdir(parents=True, exist_ok=True)
    SPAM_DIR.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 60)
    print("       THREAT-TRACE EMAIL STORAGE")
    print("=" * 60)

    print(f"\nCreated/verified:")
    print(f"Actual emails : {ACTUAL_DIR}")
    print(f"Spam emails   : {SPAM_DIR}")

    print("\nFolder structure:")
    print("emails/")
    print("├── actual/")
    print("└── spam/")

    print("\nEmail storage folders are ready.")


if __name__ == "__main__":
    create_email_folders()