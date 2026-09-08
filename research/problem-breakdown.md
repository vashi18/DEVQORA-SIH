# Problem Statement Breakdown — SIH26106

## Official Details
- **PS Number:** SIH26106
- **Organization:** All India Council for Technical Education (AICTE) — Cyber Security Cell
- **Title:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform
- **Category:** Software
- **Theme:** Blockchain & Cybersecurity
- **Idea Submission Deadline:** 30 September 2026

## Problem in Plain Words
Email remains one of the top attack vectors for phishing, fraud, and social engineering.
Current filters detect spam/phishing but stop there — they don't help investigators trace
where an attack actually came from or produce evidence usable in a cybercrime case.
This PS asks for a platform that does three things together, not separately:

1. **Detect** whether an email is malicious (AI/NLP-based)
2. **Trace** the real-world origin of the sender (GeoLocation via header/IP analysis)
3. **Produce** forensic-grade documentation of the findings (Forensic Intelligence)

## Breakdown into Modules
| Module | What it does | Key techniques |
|---|---|---|
| Threat Detection | Classify email as phishing/legitimate | NLP classifier, SPF/DKIM/DMARC checks, link analysis |
| GeoLocation | Find true sender location | Parse `Received:` header chain, IP geolocation APIs |
| Forensic Intelligence | Generate investigator-ready report | Header trace, timestamps, PDF report, chain-of-custody format |

## Ambiguities We Resolved (for MVP scope)
- **Real-time inbox scanning vs. uploaded file analysis** → We chose **uploaded `.eml` file analysis**
  for the MVP (simpler, no OAuth/IMAP complexity, easier to demo reliably).
- **"Forensic Intelligence" interpretation** → Interpreted as an auto-generated report (PDF) containing
  header trace, geolocation, and threat evidence — not a full digital forensics toolkit.
- **Scope of "AI-Powered"** → NLP-based text/header classification, not deep behavioral analysis
  (keeps model training feasible within hackathon time).

## Why This Matters
Aligns with real gaps flagged by CERT-In and cybercrime cells: phishing volume is rising, but
tools that connect detection → attribution → evidence are rare, especially for
smaller organizations that can't afford enterprise threat intel platforms.
