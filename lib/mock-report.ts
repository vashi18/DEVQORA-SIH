export type ThreatLevel = 'critical' | 'high' | 'suspicious' | 'clean'
export type AuthResult = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none'

export interface AuthCheck {
  protocol: 'SPF' | 'DKIM' | 'DMARC'
  result: AuthResult
  detail: string
}

export interface EvidenceItem {
  title: string
  detail: string
  severity: 'high' | 'medium' | 'low'
}

export interface ExtractedUrl {
  url: string
  host: string
  flags: Array<'suspicious-domain' | 'ip-based' | 'typosquatting' | 'shortener'>
}

export interface Ioc {
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email'
  value: string
  note?: string
}

export interface ThreatReport {
  fileName: string
  analyzedAt: string
  score: number // 0-100
  level: ThreatLevel
  classification: string
  overview: {
    sender: string
    senderName: string
    replyTo: string
    receiver: string
    subject: string
    date: string
  }
  auth: AuthCheck[]
  origin: {
    ip: string
    country: string
    countryCode: string
    region: string
    city: string
    isp: string
    latitude: number
    longitude: number
  }
  links: ExtractedUrl[]
  ai: {
    classification: string
    psychologicalTactic: string
    summary: string
    confidence: number
  }
  evidence: EvidenceItem[]
  iocs: Ioc[]
}

export const mockReport: ThreatReport = {
  fileName: 'invoice_urgent_payment.eml',
  analyzedAt: '2026-09-08T14:32:07Z',
  score: 87,
  level: 'high',
  classification: 'Business Email Compromise (BEC) / Phishing',
  overview: {
    sender: 'billing@paypa1-secure.com',
    senderName: 'PayPal Billing Department',
    replyTo: 'accounts.recovery@mail-inbox42.ru',
    receiver: 'finance@acme-corp.com',
    subject: 'URGENT: Invoice #INV-99231 overdue — account suspension in 24h',
    date: 'Mon, 08 Sep 2026 09:31:52 -0400',
  },
  auth: [
    { protocol: 'SPF', result: 'fail', detail: 'Sending IP 45.148.10.72 not authorized for paypa1-secure.com' },
    { protocol: 'DKIM', result: 'fail', detail: 'No valid signature found; body hash mismatch' },
    { protocol: 'DMARC', result: 'fail', detail: 'Policy p=reject; alignment failed on SPF and DKIM' },
  ],
  origin: {
    ip: '45.148.10.72',
    country: 'Russia',
    countryCode: 'RU',
    region: 'Moscow',
    city: 'Moscow',
    isp: 'PQ Hosting Plus S.R.L.',
    latitude: 55.7558,
    longitude: 37.6173,
  },
  links: [
    {
      url: 'http://paypa1-secure.com/verify?token=8f3a',
      host: 'paypa1-secure.com',
      flags: ['typosquatting', 'suspicious-domain'],
    },
    {
      url: 'http://45.148.10.72/login',
      host: '45.148.10.72',
      flags: ['ip-based', 'suspicious-domain'],
    },
    {
      url: 'https://bit.ly/3xR2payNow',
      host: 'bit.ly',
      flags: ['shortener'],
    },
    {
      url: 'https://acme-corp.com/help',
      host: 'acme-corp.com',
      flags: [],
    },
  ],
  ai: {
    classification: 'Credential Harvesting via Impersonation',
    psychologicalTactic: 'Urgency & Authority (fear of account suspension)',
    summary:
      'This email impersonates PayPal billing to pressure a finance recipient into paying an overdue invoice within 24 hours. The sender domain is a typosquat of paypal.com, all three authentication protocols fail, and the message originates from a hosting provider in Russia inconsistent with the claimed brand. Links point to a look-alike domain and a raw IP address, strong indicators of a credential-harvesting phishing attempt.',
    confidence: 94,
  },
  evidence: [
    {
      title: 'Sender domain is a typosquat of a trusted brand',
      detail: 'paypa1-secure.com uses the digit "1" in place of "l" to imitate paypal.com.',
      severity: 'high',
    },
    {
      title: 'All authentication checks failed',
      detail: 'SPF, DKIM and DMARC all failed, indicating the sender is not authorized.',
      severity: 'high',
    },
    {
      title: 'Reply-To differs from sender',
      detail: 'Replies are redirected to an unrelated .ru mailbox, a common BEC pattern.',
      severity: 'high',
    },
    {
      title: 'Origin geolocation inconsistent with brand',
      detail: 'Message originated from a hosting provider in Moscow, Russia.',
      severity: 'medium',
    },
    {
      title: 'Link points to a raw IP address',
      detail: 'One embedded link resolves directly to 45.148.10.72 instead of a domain.',
      severity: 'medium',
    },
    {
      title: 'High-pressure urgency language',
      detail: 'Subject and body threaten account suspension within 24 hours to force fast action.',
      severity: 'low',
    },
  ],
  iocs: [
    { type: 'ip', value: '45.148.10.72', note: 'Originating public IP (Moscow, RU)' },
    { type: 'domain', value: 'paypa1-secure.com', note: 'Typosquat sender domain' },
    { type: 'domain', value: 'mail-inbox42.ru', note: 'Reply-To domain' },
    { type: 'url', value: 'http://paypa1-secure.com/verify?token=8f3a' },
    { type: 'url', value: 'http://45.148.10.72/login' },
    { type: 'email', value: 'billing@paypa1-secure.com', note: 'Spoofed sender address' },
    { type: 'email', value: 'accounts.recovery@mail-inbox42.ru', note: 'Reply-To address' },
  ],
}

export const threatLevelMeta: Record<
  ThreatLevel,
  { label: string; token: string; description: string }
> = {
  critical: { label: 'Critical', token: 'danger', description: 'Confirmed malicious — do not interact' },
  high: { label: 'High Risk', token: 'danger', description: 'Strong indicators of a targeted attack' },
  suspicious: { label: 'Suspicious', token: 'warning', description: 'Multiple anomalies detected — review carefully' },
  clean: { label: 'Clean', token: 'success', description: 'No significant threats detected' },
}

export function levelFromScore(score: number): ThreatLevel {
  if (score >= 85) return 'critical'
  if (score >= 65) return 'high'
  if (score >= 35) return 'suspicious'
  return 'clean'
}
