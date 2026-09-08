import Link from 'next/link'
import {
  ArrowRight,
  ShieldCheck,
  Fingerprint,
  Globe2,
  Link2,
  BrainCircuit,
  FileSearch,
  MapPin,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { SiteHeader } from '@/components/site-header'

const capabilities = [
  {
    icon: ShieldCheck,
    title: 'Authentication forensics',
    body: 'SPF, DKIM and DMARC verification with alignment and policy detail for every message.',
  },
  {
    icon: Globe2,
    title: 'Origin & geolocation',
    body: 'Trace the originating public IP through Received headers to country, city, ISP and coordinates.',
  },
  {
    icon: Link2,
    title: 'Link intelligence',
    body: 'Extract every URL and flag suspicious domains, IP-based links and typosquatting.',
  },
  {
    icon: BrainCircuit,
    title: 'AI threat scoring',
    body: 'Classification, psychological-manipulation tactics and a plain-language summary you can act on.',
  },
  {
    icon: Fingerprint,
    title: 'Indicators of compromise',
    body: 'Structured IOCs — IPs, domains, URLs and addresses — ready to share with your SOC.',
  },
  {
    icon: FileSearch,
    title: 'Evidence-first reports',
    body: 'Every verdict is backed by the concrete forensic evidence behind it, not a black box.',
  },
]

const pipeline = [
  { step: '01', label: 'Upload .eml', detail: 'Drop the raw email file' },
  { step: '02', label: 'Parse & verify', detail: 'Headers, auth, routing' },
  { step: '03', label: 'Enrich', detail: 'Geolocation & link analysis' },
  { step: '04', label: 'Report', detail: 'Scored, evidence-backed verdict' },
]

export default function LandingPage() {
  return (
    <div className="flex min-h-dvh flex-col">
      <SiteHeader />

      <main className="flex-1">
        {/* Hero */}
        <section className="relative overflow-hidden border-b border-border">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-0 opacity-[0.15] [background-image:linear-gradient(to_right,var(--color-border)_1px,transparent_1px),linear-gradient(to_bottom,var(--color-border)_1px,transparent_1px)] [background-size:44px_44px]"
          />
          <div className="relative mx-auto max-w-6xl px-4 py-20 sm:px-6 sm:py-28">
            <div className="mx-auto max-w-3xl text-center">
              <span className="inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/10 px-3 py-1 font-mono text-xs text-primary">
                <span className="size-1.5 rounded-full bg-primary" aria-hidden="true" />
                PHISHING · BEC · FORENSIC INTELLIGENCE
              </span>
              <h1 className="mt-6 text-balance text-4xl font-semibold tracking-tight sm:text-6xl">
                Dissect any email for threats in seconds
              </h1>
              <p className="mx-auto mt-5 max-w-2xl text-pretty text-lg leading-relaxed text-muted-foreground">
                Sentinel analyzes raw <span className="font-mono text-foreground">.eml</span> files to expose
                phishing, business email compromise and impersonation — combining header forensics, IP
                geolocation and AI classification into one clear, evidence-backed report.
              </p>
              <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
                <Button
                  render={<Link href="/analyze" />}
                  nativeButton={false}
                  size="lg"
                  className="w-full sm:w-auto"
                >
                  Analyze an email
                  <ArrowRight className="size-4" aria-hidden="true" />
                </Button>
                <Button
                  render={<Link href="/report" />}
                  nativeButton={false}
                  size="lg"
                  variant="outline"
                  className="w-full sm:w-auto"
                >
                  View sample report
                </Button>
              </div>
              <p className="mt-4 font-mono text-xs text-muted-foreground">
                No account required · Files are analyzed, never shared
              </p>
            </div>
          </div>
        </section>

        {/* Pipeline */}
        <section className="border-b border-border bg-card/40">
          <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6">
            <ol className="grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-border bg-border md:grid-cols-4">
              {pipeline.map((p) => (
                <li key={p.step} className="flex flex-col gap-1 bg-card p-5">
                  <span className="font-mono text-xs text-primary">{p.step}</span>
                  <span className="text-sm font-medium text-foreground">{p.label}</span>
                  <span className="text-xs text-muted-foreground">{p.detail}</span>
                </li>
              ))}
            </ol>
          </div>
        </section>

        {/* Capabilities */}
        <section className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20">
          <div className="max-w-2xl">
            <h2 className="text-balance text-2xl font-semibold tracking-tight sm:text-3xl">
              A full forensic pass on every message
            </h2>
            <p className="mt-3 text-pretty leading-relaxed text-muted-foreground">
              The platform surfaces the technical signals analysts rely on, then explains what they mean.
              You see the evidence, not just a verdict.
            </p>
          </div>

          <div className="mt-10 grid gap-px overflow-hidden rounded-xl border border-border bg-border sm:grid-cols-2 lg:grid-cols-3">
            {capabilities.map((c) => (
              <div key={c.title} className="bg-card p-6">
                <span className="flex size-10 items-center justify-center rounded-md border border-border bg-secondary text-primary">
                  <c.icon className="size-5" aria-hidden="true" />
                </span>
                <h3 className="mt-4 font-medium text-foreground">{c.title}</h3>
                <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">{c.body}</p>
              </div>
            ))}
          </div>
        </section>

        {/* CTA */}
        <section className="border-t border-border">
          <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
            <div className="flex flex-col items-start justify-between gap-6 rounded-2xl border border-border bg-card p-8 sm:flex-row sm:items-center sm:p-10">
              <div className="flex items-start gap-4">
                <span className="flex size-11 items-center justify-center rounded-lg border border-primary/30 bg-primary/10 text-primary">
                  <MapPin className="size-5" aria-hidden="true" />
                </span>
                <div>
                  <h2 className="text-xl font-semibold tracking-tight">Ready to trace a suspicious email?</h2>
                  <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
                    Upload the <span className="font-mono text-foreground">.eml</span> and get a scored,
                    evidence-backed threat report.
                  </p>
                </div>
              </div>
              <Button
                render={<Link href="/analyze" />}
                nativeButton={false}
                size="lg"
                className="w-full shrink-0 sm:w-auto"
              >
                Analyze email
                <ArrowRight className="size-4" aria-hidden="true" />
              </Button>
            </div>
          </div>
        </section>
      </main>

      <footer className="border-t border-border">
        <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-2 px-4 py-6 text-xs text-muted-foreground sm:flex-row sm:px-6">
          <p className="font-mono">SENTINEL · Email Threat Detection & Forensic Intelligence</p>
          <p>Hackathon demo · Results shown are illustrative mock data</p>
        </div>
      </footer>
    </div>
  )
}
