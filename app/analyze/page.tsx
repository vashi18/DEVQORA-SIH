'use client'

import { useCallback, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  UploadCloud,
  FileText,
  X,
  CircleCheck,
  CircleAlert,
  Loader2,
  ShieldAlert,
  Info,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { SiteHeader } from '@/components/site-header'
import { cn } from '@/lib/utils'

type Mode = 'upload' | 'paste'

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export default function AnalyzePage() {
  const router = useRouter()
  const inputRef = useRef<HTMLInputElement>(null)

  const [mode, setMode] = useState<Mode>('upload')
  const [dragging, setDragging] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [pasted, setPasted] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [analyzing, setAnalyzing] = useState(false)

  const validateAndSet = useCallback((f: File | undefined) => {
    setError(null)
    if (!f) return
    const isEml = f.name.toLowerCase().endsWith('.eml') || f.type === 'message/rfc822'
    if (!isEml) {
      setFile(null)
      setError('Unsupported file type. Please upload a raw email in .eml format.')
      return
    }
    if (f.size > 10 * 1024 * 1024) {
      setFile(null)
      setError('File is too large. The maximum supported size is 10 MB.')
      return
    }
    setFile(f)
  }, [])

  const onDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault()
      setDragging(false)
      validateAndSet(e.dataTransfer.files?.[0])
    },
    [validateAndSet],
  )

  const canAnalyze = mode === 'upload' ? Boolean(file) : pasted.trim().length > 40

  const handleAnalyze = () => {
    if (!canAnalyze) return
    setAnalyzing(true)
    // No backend is wired up in this demo. We briefly show an indeterminate
    // processing state, then route to the report rendered from mock data.
    window.setTimeout(() => router.push('/report'), 2600)
  }

  return (
    <div className="flex min-h-dvh flex-col">
      <SiteHeader />

      <main className="mx-auto w-full max-w-3xl flex-1 px-4 py-12 sm:px-6 sm:py-16">
        <div className="mb-8">
          <h1 className="text-balance text-3xl font-semibold tracking-tight">Analyze an email</h1>
          <p className="mt-2 text-pretty leading-relaxed text-muted-foreground">
            Upload the raw <span className="font-mono text-foreground">.eml</span> file of a suspicious
            message. Sentinel parses the headers, verifies authentication and traces the origin before
            producing a scored threat report.
          </p>
        </div>

        {/* Mode toggle */}
        <div
          role="tablist"
          aria-label="Input method"
          className="mb-5 inline-flex rounded-lg border border-border bg-card p-1"
        >
          {(['upload', 'paste'] as Mode[]).map((m) => (
            <button
              key={m}
              role="tab"
              aria-selected={mode === m}
              onClick={() => {
                setMode(m)
                setError(null)
              }}
              className={cn(
                'rounded-md px-4 py-1.5 text-sm font-medium transition-colors',
                mode === m ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground',
              )}
            >
              {m === 'upload' ? 'Upload .eml' : 'Paste source'}
            </button>
          ))}
        </div>

        {mode === 'upload' ? (
          <div>
            {!file ? (
              <div
                onDragOver={(e) => {
                  e.preventDefault()
                  setDragging(true)
                }}
                onDragLeave={() => setDragging(false)}
                onDrop={onDrop}
                className={cn(
                  'flex flex-col items-center justify-center rounded-xl border-2 border-dashed p-10 text-center transition-colors sm:p-14',
                  dragging ? 'border-primary bg-primary/5' : 'border-border bg-card',
                )}
              >
                <span className="flex size-14 items-center justify-center rounded-full border border-border bg-secondary text-primary">
                  <UploadCloud className="size-7" aria-hidden="true" />
                </span>
                <p className="mt-4 text-base font-medium text-foreground">
                  Drag & drop your <span className="font-mono">.eml</span> file here
                </p>
                <p className="mt-1 text-sm text-muted-foreground">or select it from your device</p>
                <Button className="mt-5" onClick={() => inputRef.current?.click()}>
                  Browse files
                </Button>
                <input
                  ref={inputRef}
                  type="file"
                  accept=".eml,message/rfc822"
                  className="sr-only"
                  onChange={(e) => validateAndSet(e.target.files?.[0])}
                />
                <p className="mt-4 font-mono text-xs text-muted-foreground">
                  Accepted: .eml · Max 10 MB
                </p>
              </div>
            ) : (
              <div className="rounded-xl border border-border bg-card p-5">
                <div className="flex items-center gap-4">
                  <span className="flex size-11 shrink-0 items-center justify-center rounded-lg border border-border bg-secondary text-primary">
                    <FileText className="size-5" aria-hidden="true" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-medium text-foreground">{file.name}</p>
                    <p className="font-mono text-xs text-muted-foreground">{formatBytes(file.size)}</p>
                  </div>
                  <span className="inline-flex items-center gap-1.5 rounded-full border border-success/30 bg-success/10 px-2.5 py-1 text-xs font-medium text-success">
                    <CircleCheck className="size-3.5" aria-hidden="true" />
                    Ready
                  </span>
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label="Remove file"
                    onClick={() => {
                      setFile(null)
                      if (inputRef.current) inputRef.current.value = ''
                    }}
                  >
                    <X className="size-4" aria-hidden="true" />
                  </Button>
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="rounded-xl border border-border bg-card p-4">
            <label htmlFor="paste-source" className="mb-2 block text-sm font-medium">
              Paste the raw email source
            </label>
            <textarea
              id="paste-source"
              value={pasted}
              onChange={(e) => setPasted(e.target.value)}
              rows={10}
              placeholder={'Return-Path: <billing@example.com>\nReceived: from mail.example.com ...\nFrom: "Billing" <billing@example.com>\nSubject: ...'}
              className="w-full resize-y rounded-md border border-input bg-background p-3 font-mono text-xs leading-relaxed text-foreground outline-none placeholder:text-muted-foreground/60 focus-visible:ring-2 focus-visible:ring-ring"
            />
            <p className="mt-2 font-mono text-xs text-muted-foreground">
              Include full headers for the most accurate forensic results.
            </p>
          </div>
        )}

        {/* Validation message */}
        {error && (
          <div
            role="alert"
            className="mt-4 flex items-start gap-2.5 rounded-lg border border-danger/40 bg-danger/10 p-3 text-sm text-danger-foreground"
          >
            <CircleAlert className="mt-0.5 size-4 shrink-0 text-danger" aria-hidden="true" />
            <span className="text-foreground">{error}</span>
          </div>
        )}

        {/* Instructions */}
        <div className="mt-6 flex items-start gap-2.5 rounded-lg border border-border bg-secondary/40 p-3 text-sm">
          <Info className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden="true" />
          <p className="text-muted-foreground">
            In most email clients you can export an <span className="font-mono text-foreground">.eml</span> file
            via <span className="text-foreground">More actions → Download / Save as</span>, or view the original
            message to copy its full source.
          </p>
        </div>

        <div className="mt-8 flex flex-col-reverse items-center gap-3 sm:flex-row sm:justify-end">
          <p className="text-xs text-muted-foreground sm:mr-auto">
            The email is analyzed for threats and is not shared with third parties.
          </p>
          <Button size="lg" className="w-full sm:w-auto" disabled={!canAnalyze} onClick={handleAnalyze}>
            <ShieldAlert className="size-4" aria-hidden="true" />
            Analyze for threats
          </Button>
        </div>
      </main>

      {/* Indeterminate processing overlay */}
      {analyzing && (
        <div
          role="status"
          aria-live="polite"
          className="fixed inset-0 z-50 flex flex-col items-center justify-center gap-5 bg-background/90 px-6 text-center backdrop-blur-sm"
        >
          <span className="relative flex size-16 items-center justify-center">
            <span className="absolute inset-0 animate-ping rounded-full bg-primary/20" aria-hidden="true" />
            <span className="flex size-16 items-center justify-center rounded-full border border-primary/30 bg-primary/10 text-primary">
              <Loader2 className="size-7 animate-spin" aria-hidden="true" />
            </span>
          </span>
          <div>
            <p className="text-lg font-medium text-foreground">Analyzing email for threats</p>
            <p className="mt-1 font-mono text-sm text-muted-foreground">
              Parsing headers · verifying authentication · tracing origin
            </p>
          </div>
        </div>
      )}
    </div>
  )
}
