from pydantic import BaseModel, Field
from typing import List, Optional, Literal


class EmailAnalysisResponse(BaseModel):
    threat_score: int = Field(
        ge=0,
        le=100,
        description="Threat score from 0 to 100"
    )

    classification: Literal[
        "legitimate",
        "phishing",
        "bec",
        "spoofed"
    ]

    psychological_tactic: str

    originating_ip: Optional[str] = None

    forensic_summary: str

    indicators_of_compromise: List[str] = []

    # Email information
    sender: Optional[str] = None
    recipient: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[str] = None

    # Authentication results
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None

    # Geolocation
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    isp: Optional[str] = None