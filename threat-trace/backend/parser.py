from email import policy
from email.parser import BytesParser, Parser
from typing import Dict, Any


def parse_email(raw_email: str) -> Dict[str, Any]:
    """
    Parse a raw RFC 822 email and extract important forensic fields.
    """

    if not raw_email or not raw_email.strip():
        raise ValueError("Email content is empty.")

    try:
        # Parse email from raw text
        message = Parser(policy=policy.default).parsestr(raw_email)

        # Basic headers
        sender = message.get("From", "")
        recipient = message.get("To", "")
        subject = message.get("Subject", "")
        date = message.get("Date", "")

        # Extract all Received headers
        received_headers = message.get_all("Received", [])

        # Authentication headers
        authentication_results = message.get_all(
            "Authentication-Results", []
        )

        received_spf = message.get_all("Received-SPF", [])

        dkim_signature = message.get_all("DKIM-Signature", [])

        # Extract email body
        body = extract_body(message)

        return {
            "sender": sender,
            "recipient": recipient,
            "subject": subject,
            "date": date,
            "received_headers": received_headers,
            "authentication_results": authentication_results,
            "received_spf": received_spf,
            "dkim_signature": dkim_signature,
            "body": body,
        }

    except Exception as error:
        raise ValueError(f"Failed to parse email: {error}")


def extract_body(message) -> str:
    """
    Extract the readable body from an email.
    """

    # Multipart email
    if message.is_multipart():

        # Prefer plain text
        for part in message.walk():

            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            if (
                content_type == "text/plain"
                and "attachment" not in disposition
            ):
                try:
                    return part.get_content()
                except Exception:
                    pass

        # Fallback to HTML
        for part in message.walk():

            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            if (
                content_type == "text/html"
                and "attachment" not in disposition
            ):
                try:
                    return part.get_content()
                except Exception:
                    pass

        return ""

    # Non-multipart email
    try:
        return message.get_content()
    except Exception:
        return ""


def get_header(message, header_name: str) -> str:
    """
    Safely retrieve a single email header.
    """

    value = message.get(header_name)

    if value is None:
        return ""

    return str(value)