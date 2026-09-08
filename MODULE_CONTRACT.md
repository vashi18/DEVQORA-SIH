# API Contract — Email Threat Detection Platform

## Endpoint: POST /analyze

### Request (Frontend → Backend)

The frontend sends ONE raw pasted email as a single string. The backend is responsible for splitting headers from body — the frontend does NOT pre-split anything.

```json
{
  "raw_email": "Received: from mail.example.com (192.0.2.1)\nFrom: security@fakebank.com\nDate: Mon, 8 Sep 2026 10:00:00 +0000\nSubject: Urgent: Verify your account\n\nDear customer, your account will be suspended in 24 hours unless you verify your details immediately at http://fake-link.com"
}
```

**Why one field, not two:** real users copy-paste a whole email as one block. Standard email format already separates headers from body with a blank line — so the backend splits on the first blank line rather than asking the frontend to do it.

### Response (Backend → Frontend)

```json
{
  "sender_ip": "8.8.8.8",
  "location": {
    "country": "United States",
    "city": "Ashburn",
    "lat": 39.03,
    "lon": -77.5
  },
  "ip_reputation": {
    "abuse_confidence_score": 0,
    "total_reports": 201,
    "vt_reputation": 560,
    "vt_malicious_votes": 0,
    "vt_harmless_votes": 53,
    "source": "AbuseIPDB + VirusTotal"
  },
  "threat_score": 0,
  "red_flags": ["string"],
  "verdict": "safe | suspicious | malicious"
}
```

**Field notes:**
- `threat_score`: integer 0-100, combines IP reputation + LLM analysis into one number.
- `verdict`: derived from threat_score — e.g. 0-30 = safe, 31-70 = suspicious, 71-100 = malicious (Member 3/4 to confirm exact thresholds).
- `red_flags`: plain-English strings from the LLM analysis, shown as a bullet list in the UI.
- `location`: if the IP lookup fails or returns no location, backend should still return the field with null values, not omit it — keeps the frontend from crashing on missing keys.

### Backend split logic (Pydantic + FastAPI reference)

```python
from pydantic import BaseModel
from typing import List, Optional

class AnalyzeRequest(BaseModel):
    raw_email: str

class Location(BaseModel):
    country: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lng: Optional[float] = None

class IPReputation(BaseModel):
    score: int
    reports: int
    source: str

class AnalyzeResponse(BaseModel):
    sender_ip: Optional[str] = None
    location: Location
    ip_reputation: IPReputation
    threat_score: int
    red_flags: List[str]
    verdict: str

def split_email(raw_email: str) -> tuple[str, str]:
    """Splits raw pasted email into headers and body.
    Standard email format: headers end at first blank line."""
    parts = raw_email.split("\n\n", 1)
    headers = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    return headers, body
```

### Open questions
- Exact threat_score thresholds for verdict labels — confirm with Member 3.
- Should `red_flags` include severity per item (e.g. `{"flag": "...", "severity": "high"}`) or stay as plain strings? Starting with plain strings for speed — can upgrade later if time allows.