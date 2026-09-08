# API Contract - Email Threat Detection Platform

## Endpoint: POST /analyze

### Request (Frontend -> Backend)

The frontend sends ONE raw pasted email as a single string. The backend splits headers from body internally.

```json
{
  "raw_email": "full pasted email including headers and body as one string"
}
```

Backend splits on the first blank line (standard email format: headers end where body begins).

### Response (Backend -> Frontend)

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
  "classification": "legitimate | phishing | bec | spoofed",
  "psychological_tactic": "e.g. False Urgency, Authority Bias, Financial Coercion, None",
  "forensic_summary": "Two-sentence technical finding from AI analysis",
  "indicators_of_compromise": ["explicit red flags found in headers or body"]
}
```

### Field source map (who provides what)

| Field | Source |
|---|---|
| sender_ip | AI extraction (AI schema calls this originating_ip - backend renames it to sender_ip) |
| location | ip-api.com (no key needed) |
| ip_reputation | AbuseIPDB + VirusTotal combined by backend |
| threat_score | AI schema, directly |
| classification | AI schema, directly |
| psychological_tactic | AI schema, directly |
| forensic_summary | AI schema, directly |
| indicators_of_compromise | AI schema, same field name |

### Backend logic (Pydantic + FastAPI reference)

```python
from pydantic import BaseModel
from typing import List, Optional

class AnalyzeRequest(BaseModel):
    raw_email: str

class Location(BaseModel):
    country: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None

class IPReputation(BaseModel):
    abuse_confidence_score: int
    total_reports: int
    vt_reputation: int
    vt_malicious_votes: int
    vt_harmless_votes: int
    source: str

class AnalyzeResponse(BaseModel):
    sender_ip: Optional[str] = None
    location: Location
    ip_reputation: IPReputation
    threat_score: int
    classification: str
    psychological_tactic: str
    forensic_summary: str
    indicators_of_compromise: List[str]

def split_email(raw_email: str) -> tuple[str, str]:
    """Splits raw pasted email into headers and body.
    Standard email format: headers end at first blank line."""
    parts = raw_email.split("\n\n", 1)
    headers = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    return headers, body
```

**Note for Backend (Member 4):** call AbuseIPDB, VirusTotal, ip-api.com, and the AI model in parallel where possible. Take the AI's originating_ip output and use it for all three IP lookups. Rename originating_ip to sender_ip in the final response.

**Note for Frontend (Member 5):** use classification (legitimate/phishing/bec/spoofed) instead of the old verdict field. Display psychological_tactic and forensic_summary as part of the report - they add real explanatory value.

### Test data
Sample phishing and legitimate emails are in /data/samples/

### Open questions
- Confirm exact color coding for the 4 classification values in the UI (Member 5 to decide)