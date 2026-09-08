# Feasibility Notes

## Confirmed Feasible for Hackathon Timeline
- **Header parsing:** Python's built-in `email` library reliably parses `.eml` files and
  extracts `Received:` chains, `From`, `SPF/DKIM/DMARC` results — no custom parser needed
- **True-origin IP extraction:** Manually tested on synthetic samples — even when the visible
  `From` domain is spoofed, the true originating IP is recoverable from intermediate
  `Received:` header lines (see `/samples` folder)
- **Geolocation lookup:** MaxMind GeoLite2 offline database avoids live API dependency,
  making the demo resilient to network issues
- **Threat classification:** A baseline model (Naive Bayes or a small fine-tuned transformer)
  trained on SpamAssassin + Nazario corpora is achievable within a few days of the hackathon
- **PDF report generation:** Standard libraries (Python `reportlab` / `fpdf2`, or JS `pdfkit`)
  can auto-generate a structured forensic report quickly

## Constraints to Plan Around
- **VirusTotal free-tier rate limit** (4 req/min) — must cache/batch calls, don't rely on it
  live during the demo for every email
- **Real-time inbox scanning (IMAP/OAuth)** — technically possible but adds auth complexity;
  recommended as a stretch goal, not MVP
- **Model accuracy** — a hackathon-trained classifier won't match enterprise-grade accuracy;
  be upfront in the pitch that this is a proof-of-concept, not production-grade detection

## Recommended MVP Scope (for Team Lead to lock in)
1. Upload `.eml` file → parse headers + body
2. AI threat score + reason (e.g., "SPF fail", "urgency language", "suspicious link")
3. True origin IP extracted + shown on map with reputation flag (AbuseIPDB/VirusTotal)
4. One-click forensic PDF report generation

## Stretch Goals (only if MVP is done early)
- Browser extension / Outlook plugin for real-time scanning
- Case management for grouping multiple flagged emails under one investigation
- Attachment scanning via VirusTotal file API
