import { useState } from "react";
import "./App.css";

function App() {
  const [page, setPage] = useState("dashboard");
  const [emailHeaders, setEmailHeaders] = useState("");
  const [analyzing, setAnalyzing] = useState(false);

  const handleAnalyze = () => {
    if (!emailHeaders.trim()) {
      alert("Please paste email headers first.");
      return;
    }

    setAnalyzing(true);

    setTimeout(() => {
      setAnalyzing(false);
      setPage("result");
    }, 1500);
  };

  const goToAnalyze = () => {
    setPage("analyze");
    setEmailHeaders("");
    setAnalyzing(false);
  };

  return (
    <div className="app">

      {/* NAVBAR */}
      <nav className="navbar">
        <div
          className="logo"
          onClick={() => setPage("dashboard")}
        >
          CyberIntel
        </div>

        <div className="nav-links">
          <button onClick={() => setPage("dashboard")}>
            Dashboard
          </button>

          <button onClick={goToAnalyze}>
            Analyze
          </button>

          <button onClick={() => alert("Reports module coming soon.")}>
            Reports
          </button>
        </div>
      </nav>


      {/* ================= DASHBOARD ================= */}
      {page === "dashboard" && (
        <section className="dashboard-page">

          <div className="dashboard-header">
            <div>
              <span className="section-label">
                SECURITY OPERATIONS
              </span>

              <h1>Threat Dashboard</h1>

              <p>
                Overview of email threats and forensic investigations.
              </p>
            </div>

            <button
              className="dashboard-analyze-btn"
              onClick={goToAnalyze}
            >
              + Analyze Email
            </button>
          </div>


          {/* STATS */}
          <div className="dashboard-stats">

            <div className="dashboard-stat">
              <span>Emails Analyzed</span>
              <strong>1,248</strong>
              <small>Total analyzed</small>
            </div>

            <div className="dashboard-stat">
              <span>Threats Detected</span>
              <strong>327</strong>
              <small>26.2% of emails</small>
            </div>

            <div className="dashboard-stat critical-stat">
              <span>Critical Threats</span>
              <strong>42</strong>
              <small>Requires attention</small>
            </div>

            <div className="dashboard-stat">
              <span>IOCs Found</span>
              <strong>186</strong>
              <small>Indicators extracted</small>
            </div>

          </div>


          {/* DASHBOARD CARDS */}
          <div className="dashboard-grid">

            <div className="dashboard-card">
              <h2>Threat Distribution</h2>

              <p className="card-description">
                Detected threat categories
              </p>

              <div className="threat-bars">

                <div className="bar-item">
                  <div>
                    <span>Phishing</span>
                    <strong>48%</strong>
                  </div>
                  <div className="bar">
                    <div className="bar-fill" style={{ width: "48%" }} />
                  </div>
                </div>

                <div className="bar-item">
                  <div>
                    <span>Malware</span>
                    <strong>27%</strong>
                  </div>
                  <div className="bar">
                    <div className="bar-fill" style={{ width: "27%" }} />
                  </div>
                </div>

                <div className="bar-item">
                  <div>
                    <span>Spoofing</span>
                    <strong>15%</strong>
                  </div>
                  <div className="bar">
                    <div className="bar-fill" style={{ width: "15%" }} />
                  </div>
                </div>

                <div className="bar-item">
                  <div>
                    <span>Other</span>
                    <strong>10%</strong>
                  </div>
                  <div className="bar">
                    <div className="bar-fill" style={{ width: "10%" }} />
                  </div>
                </div>

              </div>
            </div>


            <div className="dashboard-card">
              <h2>Threat Severity</h2>

              <p className="card-description">
                Current severity overview
              </p>

              <div className="severity-list">

                <div>
                  <span className="severity-dot critical"></span>
                  <span>Critical</span>
                  <strong>42</strong>
                </div>

                <div>
                  <span className="severity-dot high"></span>
                  <span>High</span>
                  <strong>96</strong>
                </div>

                <div>
                  <span className="severity-dot medium"></span>
                  <span>Medium</span>
                  <strong>121</strong>
                </div>

                <div>
                  <span className="severity-dot low"></span>
                  <span>Low</span>
                  <strong>68</strong>
                </div>

              </div>
            </div>

          </div>


          {/* RECENT INVESTIGATIONS */}
          <div className="dashboard-card investigations">

            <div className="card-heading">
              <div>
                <h2>Recent Investigations</h2>
                <p className="card-description">
                  Latest analyzed emails
                </p>
              </div>
            </div>

            <div className="investigation-row">
              <div>
                <strong>Urgent Account Verification</strong>
                <span>security@suspicious-domain.com</span>
              </div>

              <span className="risk-badge high-risk">
                HIGH
              </span>
            </div>

            <div className="investigation-row">
              <div>
                <strong>Invoice Payment Required</strong>
                <span>billing@unknown-mail.net</span>
              </div>

              <span className="risk-badge critical-risk">
                CRITICAL
              </span>
            </div>

            <div className="investigation-row">
              <div>
                <strong>Password Reset Request</strong>
                <span>support@example.net</span>
              </div>

              <span className="risk-badge medium-risk">
                MEDIUM
              </span>
            </div>

          </div>

        </section>
      )}


      {/* ================= ANALYZE PAGE ================= */}
      {page === "analyze" && (
        <section className="analyze-page">

          <div className="page-header">
            <span className="section-label">
              EMAIL FORENSICS
            </span>

            <h1>Analyze Email</h1>

            <p>
              Upload an email or paste its headers to detect threats,
              trace origins and extract forensic intelligence.
            </p>
          </div>


          <div className="analyzer-card">

            <div className="input-header">
              <div>
                <h2>Email Headers</h2>

                <p>
                  Paste the complete email headers below.
                </p>
              </div>

              <label
                htmlFor="email-file"
                className="upload-btn"
              >
                📁 Choose Email File
              </label>

              <input
                type="file"
                id="email-file"
                accept=".eml,.msg"
                hidden
              />
            </div>


            <textarea
              className="email-input"
              placeholder="Paste email headers here..."
              value={emailHeaders}
              onChange={(e) =>
                setEmailHeaders(e.target.value)
              }
            />


            <div className="sample-box">
              <strong>Demo:</strong>

              <button
                onClick={() =>
                  setEmailHeaders(
`From: "Microsoft Security" <security@micros0ft-example.com>
To: user@example.com
Subject: Urgent: Your account will be suspended
Date: Tue, 8 Sep 2026 17:42:18 +0530
Message-ID: <alert-82931@micros0ft-example.com>

Received: from suspicious-mail.example.net (192.0.2.55)
    by mail.example.com with ESMTP;

Reply-To: support@random-example.net
Return-Path: <noreply@random-example.net>

Authentication-Results: mail.example.com;
    spf=fail;
    dkim=fail;
    dmarc=fail;

X-Mailer: SuspiciousMailer/1.0
Content-Type: text/html`
                  )
                }
              >
                Load Sample Headers
              </button>
            </div>


            <button
              className="analyze-main-btn"
              onClick={handleAnalyze}
              disabled={analyzing}
            >
              {analyzing
                ? "⏳ Analyzing..."
                : "🔍 Analyze Email"}
            </button>

          </div>

        </section>
      )}


      {/* ================= RESULT PAGE ================= */}
      {page === "result" && (
        <section className="results-page">

          <div className="result-header">

            <div>
              <span className="section-label">
                ANALYSIS COMPLETE
              </span>

              <h1>Threat Analysis</h1>

              <p>
                AI-powered analysis of the submitted email.
              </p>
            </div>

            <button
              className="back-btn"
              onClick={goToAnalyze}
            >
              ← Analyze Another
            </button>

          </div>


          {/* THREAT SCORE */}
          <div className="threat-score-card">

            <div>
              <span className="score-label">
                THREAT LEVEL
              </span>

              <h2>HIGH RISK</h2>

              <p>
                Phishing activity detected
              </p>
            </div>

            <div className="score-number">
              <strong>87</strong>
              <span>/100</span>
            </div>

          </div>


          {/* FINDINGS */}
          <div className="result-grid">

            <div className="result-card">

              <h2>Threat Findings</h2>

              <div className="finding">
                <span>⚠</span>
                <div>
                  <strong>Suspicious URL detected</strong>
                  <p>Potential phishing infrastructure</p>
                </div>
              </div>

              <div className="finding">
                <span>⚠</span>
                <div>
                  <strong>SPF verification failed</strong>
                  <p>Sender authorization could not be verified</p>
                </div>
              </div>

              <div className="finding">
                <span>⚠</span>
                <div>
                  <strong>DKIM verification failed</strong>
                  <p>Email signature validation failed</p>
                </div>
              </div>

              <div className="finding">
                <span>⚠</span>
                <div>
                  <strong>DMARC verification failed</strong>
                  <p>Domain authentication policy failed</p>
                </div>
              </div>

              <div className="finding">
                <span>⚠</span>
                <div>
                  <strong>Suspicious sender domain</strong>
                  <p>Domain resembles a trusted organization</p>
                </div>
              </div>

            </div>


            {/* EMAIL INFORMATION */}
            <div className="result-card">

              <h2>Email Intelligence</h2>

              <div className="info-row">
                <span>Sender</span>
                <strong>
                  security@micros0ft-example.com
                </strong>
              </div>

              <div className="info-row">
                <span>Source IP</span>
                <strong>185.199.110.42</strong>
              </div>

              <div className="info-row">
                <span>Domain</span>
                <strong>micros0ft-example.com</strong>
              </div>

              <div className="info-row">
                <span>Location</span>
                <strong>Unknown</strong>
              </div>

            </div>

          </div>


          {/* IOCs */}
          <div className="result-card">

            <h2>Indicators of Compromise</h2>

            <div className="ioc-grid">

              <div className="ioc-card">
                <span>IP ADDRESS</span>
                <strong>185.199.110.42</strong>
                <small className="ioc-high">HIGH RISK</small>
              </div>

              <div className="ioc-card">
                <span>DOMAIN</span>
                <strong>micros0ft-example.com</strong>
                <small className="ioc-high">HIGH RISK</small>
              </div>

              <div className="ioc-card">
                <span>EMAIL</span>
                <strong>security@micros0ft-example.com</strong>
                <small className="ioc-medium">MEDIUM RISK</small>
              </div>

            </div>

          </div>


          {/* AI SUMMARY */}
          <div className="ai-summary">

            <span className="section-label">
              AI INVESTIGATION SUMMARY
            </span>

            <h2>Potential phishing campaign detected</h2>

            <p>
              The analyzed email contains multiple authentication
              failures and indicators associated with phishing activity.
              The sender domain appears suspicious and the originating
              infrastructure requires further investigation.
            </p>

          </div>


          {/* GEOLOCATION */}
          <div className="result-card">

            <h2>🌍 Geolocation Intelligence</h2>

            <div className="geo-grid">

              <div>
                <span>IP Address</span>
                <strong>185.199.110.42</strong>
              </div>

              <div>
                <span>Country</span>
                <strong>Unknown</strong>
              </div>

              <div>
                <span>ISP</span>
                <strong>Unknown</strong>
              </div>

              <div>
                <span>ASN</span>
                <strong>Unknown</strong>
              </div>

            </div>

          </div>


          {/* TIMELINE */}
          <div className="result-card">

            <h2>Forensic Timeline</h2>

            <div className="timeline">

              <div className="timeline-item">
                <span></span>
                <div>
                  <strong>Email received</strong>
                  <p>17:42:15</p>
                </div>
              </div>

              <div className="timeline-item">
                <span></span>
                <div>
                  <strong>Authentication checks failed</strong>
                  <p>17:42:16</p>
                </div>
              </div>

              <div className="timeline-item">
                <span></span>
                <div>
                  <strong>Suspicious domain identified</strong>
                  <p>17:42:17</p>
                </div>
              </div>

              <div className="timeline-item">
                <span></span>
                <div>
                  <strong>Threat classified as HIGH RISK</strong>
                  <p>17:42:18</p>
                </div>
              </div>

            </div>

          </div>


          <div className="result-actions">

            <button
              className="dashboard-analyze-btn"
              onClick={() => setPage("dashboard")}
            >
              ← Back to Dashboard
            </button>

          </div>

        </section>
      )}

    </div>
  );
}

export default App;