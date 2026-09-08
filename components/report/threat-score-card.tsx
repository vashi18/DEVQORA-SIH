import { AlertTriangle, ShieldCheck, ShieldAlert, ShieldX } from 'lucide-react'
import { type ThreatLevel, threatLevelMeta } from '@/lib/mock-report'
import { cn } from '@/lib/utils'

const tokenClasses: Record<
  string,
  { text: string; ring: string; track: string; chip: string; icon: typeof ShieldX }
> = {
  danger: {
    text: 'text-danger',
    ring: 'stroke-danger',
    track: 'stroke-danger/15',
    chip: 'border-danger/40 bg-danger/10 text-danger',
    icon: ShieldX,
  },
  warning: {
    text: 'text-warning',
    ring: 'stroke-warning',
    track: 'stroke-warning/15',
    chip: 'border-warning/40 bg-warning/10 text-warning',
    icon: ShieldAlert,
  },
  success: {
    text: 'text-success',
    ring: 'stroke-success',
    track: 'stroke-success/15',
    chip: 'border-success/40 bg-success/10 text-success',
    icon: ShieldCheck,
  },
}

interface ThreatScoreCardProps {
  score: number
  level: ThreatLevel
  classification: string
}

export function ThreatScoreCard({ score, level, classification }: ThreatScoreCardProps) {
  const meta = threatLevelMeta[level]
  const styles = tokenClasses[meta.token]
  const Icon = styles.icon

  const radius = 52
  const circumference = 2 * Math.PI * radius
  const dash = (score / 100) * circumference

  return (
    <div className="grid gap-6 rounded-xl border border-border bg-card p-6 sm:grid-cols-[auto_1fr] sm:items-center sm:gap-8 sm:p-8">
      {/* Gauge */}
      <div className="relative mx-auto flex size-36 items-center justify-center">
        <svg viewBox="0 0 120 120" className="size-36 -rotate-90" aria-hidden="true">
          <circle cx="60" cy="60" r={radius} fill="none" strokeWidth="10" className={styles.track} />
          <circle
            cx="60"
            cy="60"
            r={radius}
            fill="none"
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={`${dash} ${circumference}`}
            className={styles.ring}
          />
        </svg>
        <div className="absolute flex flex-col items-center">
          <span className={cn('font-mono text-4xl font-semibold tabular-nums', styles.text)}>{score}</span>
          <span className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">/ 100</span>
        </div>
      </div>

      {/* Verdict */}
      <div>
        <div className="flex flex-wrap items-center gap-2">
          <span
            className={cn(
              'inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-sm font-semibold',
              styles.chip,
            )}
          >
            <Icon className="size-4" aria-hidden="true" />
            {meta.label}
          </span>
          <span className="font-mono text-xs text-muted-foreground">THREAT SCORE</span>
        </div>

        <h1 className="mt-3 text-balance text-2xl font-semibold tracking-tight sm:text-3xl">
          {classification}
        </h1>
        <p className="mt-2 flex items-center gap-2 text-sm text-muted-foreground">
          <AlertTriangle className={cn('size-4 shrink-0', styles.text)} aria-hidden="true" />
          {meta.description}
        </p>
      </div>
    </div>
  )
}
