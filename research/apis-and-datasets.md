# APIs & Datasets Reference

## APIs

### IP Geolocation
| API | Free Tier | Notes |
|---|---|---|
| [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | Free, downloadable DB | Offline lookup, no rate limit, best for demo reliability |
| [IPinfo.io](https://ipinfo.io/) | 50,000 requests/month free | Simple REST API, good docs |
| [ip-api.com](https://ip-api.com/) | 45 requests/min free (non-commercial) | Fast, no key required for basic use |

### Threat Intelligence / Reputation
| API | Free Tier | Notes |
|---|---|---|
| [VirusTotal API v3](https://developers.virustotal.com/reference/overview) | 4 requests/min, 500/day | Check IP/URL/file reputation; needs API key |
| [AbuseIPDB](https://www.abuseipdb.com/api.html) | 1,000 checks/day free | Returns abuse confidence score for an IP; needs API key |
| [PhishTank API](https://phishtank.org/api_info.php) | Free | URL blacklist lookup |

### Email Parsing Libraries (no external API needed)
- Python `email` module (standard library) — parses raw `.eml` headers/body
- `mail-parser` (Python package) — higher-level wrapper, extracts headers cleanly

## Datasets

### Phishing/Spam (labeled, for training the classifier)
- **Nazario Phishing Corpus** — real phishing emails with headers, search GitHub mirrors
  ("nazario phishing corpus github")
- **SpamAssassin Public Corpus** — ham + spam, raw format with headers,
  spamassassin.apache.org/old/publiccorpus
- **IWSPA-AP Dataset** — academic anti-phishing shared task dataset, header-preserved

### Legitimate Email (for negative/ham examples)
- **Enron Email Dataset** — large legitimate corpus (Kaggle: search "Enron email dataset")

### Our own synthetic samples (in `/samples` folder)
- 3 synthetic phishing `.eml`-style `.txt` files (fake bank, fake delivery, fake IT helpdesk)
- 3 synthetic legitimate `.eml`-style `.txt` files (Google alert, GitHub notification, org notice)
- Built with realistic headers so header-parsing/geolocation logic can be tested without
  relying on real captured phishing data (safer for public repo + live demo)

## Rate Limit Notes for Backend/AI Team
- VirusTotal free tier is the tightest constraint (4/min) — cache results, don't call on every
  page load during demo
- Prefer MaxMind GeoLite2 (offline DB) over live geolocation APIs for the demo to avoid any
  network dependency during presentation
