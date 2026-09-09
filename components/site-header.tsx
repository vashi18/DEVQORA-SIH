import Link from 'next/link'
import { ShieldCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'

export function SiteHeader() {
  return (
    <header className="sticky top-0 z-40 border-b border-border/80 bg-background/80 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-4 sm:px-6">
        <Link href="/" className="flex items-center gap-2.5" aria-label="Sentinel home">
          <span className="flex size-9 items-center justify-center rounded-md border border-primary/30 bg-primary/10 text-primary">
            <ShieldCheck className="size-5" aria-hidden="true" />
          </span>
          <span className="flex flex-col leading-none">
            <span className="font-mono text-sm font-semibold tracking-tight text-foreground">SENTINEL</span>
            <span className="text-[11px] text-muted-foreground">Email Forensics</span>
          </span>
        </Link>

        <nav className="flex items-center gap-1 sm:gap-2">
          <Button
            render={<Link href="/report" />}
            nativeButton={false}
            variant="ghost"
            size="sm"
            className="hidden text-muted-foreground hover:text-foreground sm:inline-flex"
          >
            Sample report
          </Button>
          <Button render={<Link href="/analyze" />} nativeButton={false} size="sm">
            Analyze email
          </Button>
        </nav>
      </div>
    </header>
  )
}
