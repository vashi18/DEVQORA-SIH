import type { LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'

interface SectionCardProps {
  id?: string
  label: string
  title: string
  icon: LucideIcon
  action?: React.ReactNode
  className?: string
  children: React.ReactNode
}

export function SectionCard({ id, label, title, icon: Icon, action, className, children }: SectionCardProps) {
  return (
    <section
      id={id}
      className={cn('flex flex-col overflow-hidden rounded-xl border border-border bg-card', className)}
    >
      <header className="flex items-center justify-between gap-3 border-b border-border px-5 py-4">
        <div className="flex items-center gap-3">
          <span className="flex size-9 items-center justify-center rounded-md border border-border bg-secondary text-primary">
            <Icon className="size-4.5" aria-hidden="true" />
          </span>
          <div>
            <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">{label}</p>
            <h2 className="text-sm font-semibold text-foreground">{title}</h2>
          </div>
        </div>
        {action}
      </header>
      <div className="flex-1 p-5">{children}</div>
    </section>
  )
}

export function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1 py-2.5">
      <dt className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">{label}</dt>
      <dd className="text-sm text-foreground">{children}</dd>
    </div>
  )
}
