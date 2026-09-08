# Existing Solutions & Gaps

## What Already Exists

### 1. Microsoft Defender for Office 365
- Enterprise-grade phishing/malware filtering for Outlook/M365
- Strong detection accuracy, integrates with org-wide security
- **Gap:** Closed ecosystem, expensive, no exposed forensic report for investigators outside the org

### 2. Google Workspace Phishing Protection
- ML-based phishing detection built into Gmail
- Automatic warnings on suspicious links/senders
- **Gap:** No geolocation attribution, no exportable forensic evidence — flags and blocks, nothing else

### 3. SpamAssassin (open source)
- Rule-based + Bayesian spam/phishing scoring
- Widely used, customizable, free
- **Gap:** No AI/NLP context understanding, no IP geolocation, no report generation — just a score

### 4. VirusTotal / AbuseIPDB (as standalone tools)
- Excellent for checking reputation of a URL/IP/file
- **Gap:** Not email-specific — doesn't parse headers or classify email content; needs to be
  integrated into a larger pipeline (which is exactly what this PS asks for)

### 5. PhishTank
- Community-reported phishing URL database
- **Gap:** Reactive only (relies on prior reports), no real-time detection or forensic tooling

## Summary of the Gap
No existing accessible tool combines all three: **AI detection + sender geolocation + forensic
report generation** in one platform, especially not one that's open/affordable for smaller
organizations, educational institutions, or state-level cybercrime cells. Enterprise tools
(Microsoft/Google) solve detection but treat geolocation/forensics as out of scope. Open-source
tools (SpamAssassin) solve detection cheaply but lack AI context and investigative output.

This is the gap SIH26106 is asking teams to fill.

## Sources
- CERT-In phishing advisories (cert-in.org.in)
- I4C (Indian Cyber Crime Coordination Centre) resources (cybercrime.gov.in)
- Microsoft Defender for Office 365 documentation
- Google Workspace security documentation
