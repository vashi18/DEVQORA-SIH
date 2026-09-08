import Link from 'next/link'
import {
  ArrowLeft,
  ShieldQuestion,
  Mail,
  KeyRound,
  Globe2,
  Link2,
  BrainCircuit,
  Fingerprint,
  MapPin,
  CircleCheck,
  CircleX,
  CircleAlert,
  ExternalLink,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { SiteHeader } from '@/components/site-header'
import { SectionCard, Field } from '@/components/report/section-card'
import { ThreatScoreCard } from '@/components/report/threat-score-card'
import { mockReport, type AuthResult, type EvidenceItem, type ExtractedUrl, type Ioc } from '@/lib/mock-report'
import { cn } from '@/lib/utils'

const flagLabels: Record<ExtractedUrl['flags'][number], string> = {
  'suspicious-domain': 'Suspicious domain',
  'ip-based': 'IP-based URL',
  typosquatting: 'Typosquatting',
  shortener: 'URL shortener',
}

function AuthBadge({ result }: { result: AuthResult }) {
  const map: Record<AuthResult, { label: string; cls: string; icon: typeof CircleCheck }> = {
    pass: { label: 'PASS', cls: 'border-success/40 bg-success/10 text-success', icon: CircleCheck },
    fail: { label: 'FAIL', cls: 'border-danger/40 bg-danger/10 text-danger', icon: CircleX },
    softfail: { label: 'SOFTFAIL', cls: 'border-warning/40 bg-warning/10 text-warning', icon: CircleAlert },
    neutral: { label: 'NEUTRAL', cls: 'border-border bg-secondary text-muted-foreground', icon: CircleAlert },
    none: { label: 'NONE', cls: 'border-border bg-secondary text-muted-foreground', icon: CircleAlert },
  }
  const { label, cls, icon: Icon } = map[result]
  return (
    <span className={cn('inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-xs font-medium', cls)}>
      <Icon className="size-3.5" aria-hidden="true" />
      {label}
    </span>
  )
}

function SeverityDot({ severity }: { severity: EvidenceItem['severity'] }) {
  const cls =
    severity === 'high' ? 'bg-danger' : severity === 'medium' ? 'bg-warning' : 'bg-muted-foreground'
  return <span className={cn('mt-1.5 size-2 shrink-0 rounded-full', cls)} aria-hidden="true" />
}

const iocTypeLabels: Record<Ioc['type'], string> = {
  ip: 'IP',
  domain: 'DOMAIN',
  url: 'URL',
  hash: 'HASH',
  email: 'EMAIL',
}

export default function ReportPage() {
  const r = mockReport
  const analyzed = new Date(r.analyzedAt)

  return (
    <div className="flex min-h-dvh flex-col">
      <SiteHeader />

      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 sm:px-6 sm:py-10">
        {/* Toolbar */}
        <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <Button
              render={<Link href="/analyze" />}
              nativeButton={false}
              variant="ghost"
              size="sm"
              className="-ml-2 mb-2 text-muted-foreground hover:text-foreground"
            >
              <ArrowLeft className="size-4" aria-hidden="true" />
              Analyze another
            </Button>
            <h1 className="font-mono text-sm text-foreground sm:text-base">{r.fileName}</h1>
            <p className="mt-0.5 font-mono text-xs text-muted-foreground">
              Analyzed {analyzed.toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' })} UTC
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm">Export report</Button>
            <Button variant="outline" size="sm">Copy IOCs</Button>
          </div>
        </div>

        {/* Score hero */}
        <ThreatScoreCard score={r.score} level={r.level} classification={r.classification} />

        {/* A. Why suspicious — most prominent */}
        <div className="mt-6">
          <SectionCard
            id="evidence"
            label="Section A"
            title="Why this email is suspicious"
            icon={ShieldQuestion}
          >
            <ul className="flex flex-col divide-y divide-border">
              {r.evidence.map((e) => (
                <li key={e.title} className="flex items-start gap-3 py-3 first:pt-0 last:pb-0">
                  <SeverityDot severity={e.severity} />
                  <div>
                    <p className="text-sm font-medium text-foreground">{e.title}</p>
                    <p className="mt-0.5 text-sm leading-relaxed text-muted-foreground">{e.detail}</p>
                  </div>
                  <span
                    className={cn(
                      'ml-auto shrink-0 font-mono text-[11px] uppercase tracking-wider',
                      e.severity === 'high'
                        ? 'text-danger'
                        : e.severity === 'medium'
                          ? 'text-warning'
                          : 'text-muted-foreground',
                    )}
                  >
                    {e.severity}
                  </span>
                </li>
              ))}
            </ul>
          </SectionCard>
        </div>

        <div className="mt-6 grid gap-6 lg:grid-cols-2">
          {/* B. Email overview */}
          <SectionCard label="Section B" title="Email overview" icon={Mail}>
            <dl className="divide-y divide-border">
              <Field label="From">
                <span className="font-medium">{r.overview.senderName}</span>{' '}
                <span className="font-mono text-muted-foreground">&lt;{r.overview.sender}&gt;</span>
              </Field>
              <Field label="Reply-To">
                <span className="font-mono text-danger">{r.overview.replyTo}</span>
              </Field>
              <Field label="To">
                <span className="font-mono">{r.overview.receiver}</span>
              </Field>
              <Field label="Subject">{r.overview.subject}</Field>
              <Field label="Date">
                <span className="font-mono text-muted-foreground">{r.overview.date}</span>
              </Field>
            </dl>
          </SectionCard>

          {/* C. Authentication */}
          <SectionCard label="Section C" title="Authentication" icon={KeyRound}>
            <ul className="flex flex-col gap-3">
              {r.auth.map((a) => (
                <li key={a.protocol} className="rounded-lg border border-border bg-secondary/30 p-3">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-sm font-semibold text-foreground">{a.protocol}</span>
                    <AuthBadge result={a.result} />
                  </div>
                  <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">{a.detail}</p>
                </li>
              ))}
            </ul>
          </SectionCard>

          {/* D. Origin intelligence */}
          <SectionCard label="Section D" title="Origin intelligence" icon={Globe2}>
            <div className="mb-4 flex items-center gap-3 rounded-lg border border-border bg-secondary/30 p-3">
              <MapPin className="size-5 shrink-0 text-primary" aria-hidden="true" />
              <div>
                <p className="text-sm font-medium text-foreground">
                  {r.origin.city}, {r.origin.region}, {r.origin.country}{' '}
                  <span className="font-mono text-muted-foreground">({r.origin.countryCode})</span>
                </p>
                <p className="font-mono text-xs text-muted-foreground">
                  {r.origin.latitude.toFixed(4)}, {r.origin.longitude.toFixed(4)}
                </p>
              </div>
            </div>
            <dl className="grid grid-cols-2 gap-x-6 divide-border">
              <Field label="Originating IP">
                <span className="font-mono">{r.origin.ip}</span>
              </Field>
              <Field label="ISP">{r.origin.isp}</Field>
              <Field label="Country">
                {r.origin.country} <span className="font-mono text-muted-foreground">({r.origin.countryCode})</span>
              </Field>
              <Field label="Region / City">
                {r.origin.region} · {r.origin.city}
              </Field>
            </dl>
          </SectionCard>

          {/* F. AI intelligence */}
          <SectionCard label="Section F" title="AI intelligence" icon={BrainCircuit}>
            <div className="flex flex-col gap-4">
              <div className="flex flex-wrap gap-2">
                <span className="rounded-md border border-primary/30 bg-primary/10 px-2.5 py-1 text-xs font-medium text-primary">
                  {r.ai.classification}
                </span>
                <span className="rounded-md border border-warning/30 bg-warning/10 px-2.5 py-1 text-xs font-medium text-warning">
                  {r.ai.psychologicalTactic}
                </span>
              </div>
              <div>
                <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">AI summary</p>
                <p className="mt-1.5 text-sm leading-relaxed text-foreground">{r.ai.summary}</p>
              </div>
              <div className="flex items-center gap-3">
                <span className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                  Confidence
                </span>
                <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-secondary">
                  <div className="h-full rounded-full bg-primary" style={{ width: `${r.ai.confidence}%` }} />
                </div>
                <span className="font-mono text-sm tabular-nums text-foreground">{r.ai.confidence}%</span>
              </div>
            </div>
          </SectionCard>
        </div>

        {/* E. Link intelligence */}
        <div className="mt-6">
          <SectionCard label="Section E" title="Link intelligence" icon={Link2}>
            <ul className="flex flex-col divide-y divide-border">
              {r.links.map((l) => (
                <li key={l.url} className="flex flex-col gap-2 py-3 first:pt-0 last:pb-0 sm:flex-row sm:items-center sm:justify-between">
                  <div className="min-w-0">
                    <p className="flex items-center gap-1.5 truncate font-mono text-sm text-foreground">
                      <ExternalLink className="size-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                      {l.url}
                    </p>
                    <p className="mt-0.5 font-mono text-xs text-muted-foreground">host: {l.host}</p>
                  </div>
                  <div className="flex shrink-0 flex-wrap gap-1.5">
                    {l.flags.length === 0 ? (
                      <span className="inline-flex items-center gap-1 rounded-md border border-success/30 bg-success/10 px-2 py-0.5 text-xs text-success">
                        <CircleCheck className="size-3" aria-hidden="true" />
                        No flags
                      </span>
                    ) : (
                      l.flags.map((f) => (
                        <span
                          key={f}
                          className="inline-flex items-center gap-1 rounded-md border border-danger/40 bg-danger/10 px-2 py-0.5 text-xs font-medium text-danger"
                        >
                          <CircleAlert className="size-3" aria-hidden="true" />
                          {flagLabels[f]}
                        </span>
                      ))
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </SectionCard>
        </div>

        {/* G. IOCs */}
        <div className="mt-6">
          <SectionCard
            label="Section G"
            title="Indicators of compromise"
            icon={Fingerprint}
            action={
              <span className="font-mono text-xs text-muted-foreground">{r.iocs.length} indicators</span>
            }
          >
            <ul className="grid gap-2 sm:grid-cols-2">
              {r.iocs.map((ioc) => (
                <li
                  key={`${ioc.type}-${ioc.value}`}
                  className="flex items-start gap-3 rounded-lg border border-border bg-secondary/30 p-3"
                >
                  <span className="mt-0.5 rounded border border-border bg-background px-1.5 py-0.5 font-mono text-[10px] font-semibold tracking-wider text-primary">
                    {iocTypeLabels[ioc.type]}
                  </span>
                  <div className="min-w-0">
                    <p className="truncate font-mono text-sm text-foreground">{ioc.value}</p>
                    {ioc.note && <p className="mt-0.5 text-xs text-muted-foreground">{ioc.note}</p>}
                  </div>
                </li>
              ))}
            </ul>
          </SectionCard>
        </div>

        <p className="mt-8 text-center font-mono text-xs text-muted-foreground">
          Results shown are illustrative mock data for demonstration purposes.
        </p>
      </main>
    </div>
  )
}
