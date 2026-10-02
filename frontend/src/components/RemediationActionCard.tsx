"use client";

import { useState } from "react";
import type { Role } from "../lib/api";
import type { Finding, Remediation, Severity } from "../lib/types";

// The primary action follows the real lifecycle in
// services/remediation/app/approval_matrix.py: Approve -> (2nd approval) ->
// Mark applied -> Roll back. NetAuditor has no device push, so "Mark applied"
// records that an operator ran the script by hand. Every gate the backend
// would refuse is shown here first, so a disabled button always says why.

type Tone = "pass" | "fail" | "wait" | "na";
interface Gate { label: string; tone: Tone; detail: string; blocks: boolean }
type ActionKind = "approve" | "apply" | "rollback" | "none";

export function deriveCardState(r: Remediation, role: Role) {
  const preflight = r.preflight_status ?? r.preflight?.status ?? "UNAVAILABLE";
  const flags = r.risk_flags ?? r.preflight?.risk_flags ?? [];
  const decision = r.decision;
  const broken = r.twin?.modeled ? r.twin.broken : 0;
  const roleDenied = role === "auditor"
    || (role === "operator" && !!decision && (decision.risk === "HIGH" || decision.blast_radius_count > 0));

  const gates: Gate[] = [
    r.source === "template"
      ? { label: "Source", tone: "pass", detail: r.template_name, blocks: false }
      : { label: "Source", tone: "fail", detail: "AI draft, no reviewed template", blocks: true },
    preflight === "SAFE"
      ? { label: "Preflight", tone: "pass", detail: "SAFE", blocks: false }
      : preflight === "RISK_FLAGS"
        ? { label: "Preflight", tone: "fail", detail: `${flags.length} risk flag${flags.length === 1 ? "" : "s"}`, blocks: true }
        : { label: "Preflight", tone: "wait", detail: "No Batfish snapshot", blocks: true },
    !r.twin?.modeled
      ? { label: "Reachability", tone: "na", detail: "Not modeled", blocks: false }
      : broken > 0
        ? { label: "Reachability", tone: "fail", detail: `${broken} critical path${broken === 1 ? "" : "s"} break`, blocks: true }
        : { label: "Reachability", tone: "pass", detail: `${r.twin.checks.length} paths preserved`, blocks: false },
    !decision
      ? { label: "Policy", tone: "na", detail: "Unclassified", blocks: false }
      : decision.action === "BLOCK"
        ? { label: "Policy", tone: "fail", detail: decision.reason, blocks: true }
        : decision.action === "DUAL_APPROVAL"
          ? { label: "Policy", tone: "wait", detail: `2-person rule · ${r.dual_approval?.received ?? 0} of ${r.dual_approval?.required ?? 2}`, blocks: false }
          : { label: "Policy", tone: "pass", detail: `${decision.risk} risk · ${decision.action.replace("_", " ").toLowerCase()}`, blocks: false },
    roleDenied
      ? { label: "Your role", tone: "fail", detail: role === "auditor" ? "Auditors cannot approve" : "Needs Security Lead", blocks: true }
      : { label: "Your role", tone: "pass", detail: role, blocks: false },
  ];

  let kind: ActionKind = "approve";
  let label = "Approve fix";
  let note: string | null = null;
  if (r.rollback_status === "ROLLED_BACK") { kind = "none"; label = "Rolled back"; note = "Regenerate to propose a new fix."; }
  else if (r.applied_at) { kind = "rollback"; label = "Roll back"; note = `Applied ${new Date(r.applied_at).toLocaleString()}.`; }
  else if (r.approval_status === "APPROVED") { kind = "apply"; label = "Mark applied"; note = "Run the script on the device, then record it here."; }
  else if (r.approval_status === "REJECTED") { kind = "none"; label = "Rejected"; note = "Kept in the audit trail."; }
  else if (decision?.action === "DUAL_APPROVAL") {
    const received = r.dual_approval?.received ?? 0;
    label = received > 0 ? "Add second approval" : "Approve · 1 of 2";
  }

  const blocker = kind === "approve" ? gates.find((g) => g.blocks) : undefined;
  if (blocker) note = r.source === "agentic_rag"
    ? "Verify against vendor documentation and apply out-of-band, or reject."
    : `${blocker.label}: ${blocker.detail}`;
  return { gates, kind, label, note, enabled: kind !== "none" && !blocker, flags, preflight };
}

const SEVERITY: Record<Severity, { chip: string; line: string }> = {
  CRITICAL: { chip: "bg-[color:var(--critical)] text-[color:var(--bg)]", line: "bg-[color:var(--critical-bg)]" },
  HIGH: { chip: "bg-[color:var(--high-bg)] text-[color:var(--high)] border border-[color:var(--high)]", line: "bg-[color:var(--high-bg)]" },
  MEDIUM: { chip: "bg-[color:var(--medium-bg)] text-[color:var(--medium)]", line: "bg-[color:var(--medium-bg)]" },
  LOW: { chip: "text-[color:var(--muted)] border border-[color:var(--line-strong)]", line: "bg-[color:var(--panel2)]" },
};

const TONE: Record<Tone, string> = {
  pass: "text-[color:var(--teal)]",
  fail: "text-[color:var(--critical)]",
  wait: "text-[color:var(--medium)]",
  na: "text-[color:var(--dim)]",
};

function GateIcon({ tone }: { tone: Tone }) {
  const d = { pass: "M3 8.5l3 3 7-7", fail: "M4 4l8 8M12 4l-8 8", wait: "M8 4v4l3 2", na: "M4 8h8" }[tone];
  return (
    <svg viewBox="0 0 16 16" aria-hidden="true" className={`h-3.5 w-3.5 shrink-0 ${TONE[tone]}`} fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      {tone === "wait" && <circle cx="8" cy="8" r="6" />}
      <path d={d} />
    </svg>
  );
}

function Script({ text }: { text: string }) {
  return (
    <ol className="m-0 list-none overflow-x-auto bg-[color:var(--console)] py-2 text-[12px] leading-5 [font-family:var(--mono)]">
      {text.trimEnd().split("\n").map((line, i) => (
        <li key={i} className="flex whitespace-pre">
          <span className="w-9 shrink-0 select-none pr-3 text-right text-[color:var(--console-muted)] tabular-nums">{i + 1}</span>
          <span className={line.trimStart().startsWith("!") || line.trimStart().startsWith("#") ? "text-[color:var(--console-muted)]" : "text-[color:var(--console-ink)]"}>{line || " "}</span>
        </li>
      ))}
    </ol>
  );
}

export interface RemediationActionCardProps {
  finding: Finding;
  remediation: Remediation;
  device: { hostname: string; vendor: string; os?: string | null };
  role: Role;
  busy?: boolean;
  onApprove: () => void;
  onReject: () => void;
  onMarkApplied: () => void;
  onRollback: (reason: string) => void;
}

export default function RemediationActionCard({ finding, remediation, device, role, busy = false, onApprove, onReject, onMarkApplied, onRollback }: RemediationActionCardProps) {
  const state = deriveCardState(remediation, role);
  const sev = SEVERITY[finding.severity];
  const [copied, setCopied] = useState<"idle" | "done" | "failed">("idle");
  const [rollbackOpen, setRollbackOpen] = useState(false);
  const [reason, setReason] = useState("");
  const lines = (finding.source_lines ?? []).map((l) => (typeof l === "number" ? { line: l, text: "" } : l)).filter((l) => l.text);
  const isDraft = remediation.source === "agentic_rag";

  async function copy() {
    try { await navigator.clipboard.writeText(remediation.script); setCopied("done"); }
    catch { setCopied("failed"); }
    setTimeout(() => setCopied("idle"), 1600);
  }

  function primary() {
    if (state.kind === "approve") onApprove();
    else if (state.kind === "apply") onMarkApplied();
    else if (state.kind === "rollback") setRollbackOpen((open) => !open);
  }

  return (
    <article aria-labelledby={`rac-${finding.control_id}`} className="overflow-hidden rounded-md border border-[color:var(--line)] bg-[color:var(--panel)] text-[13px] leading-[1.45] text-[color:var(--ink)] [box-shadow:var(--shadow-sm)]">
      <header className="grid gap-1.5 border-b border-[color:var(--line)] px-4 py-3">
        <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-[12px]">
          <span className={`rounded-sm px-1.5 py-px text-[11px] font-semibold tracking-[0.06em] ${sev.chip}`}>{finding.severity}</span>
          <span className="text-[color:var(--ink)] [font-family:var(--mono)]">{finding.control_id}</span>
          <span className="text-[color:var(--muted)]">{finding.framework}</span>
          <span className="ml-auto text-[color:var(--muted)]">Risk <b className="font-semibold text-[color:var(--ink)] tabular-nums [font-family:var(--mono)]">{finding.risk_score.toFixed(1)}</b></span>
        </div>
        <h3 id={`rac-${finding.control_id}`} className="m-0 text-[15px] font-semibold leading-snug [text-wrap:balance]">{finding.title}</h3>
        <p className="m-0 flex flex-wrap gap-x-2 text-[12px] text-[color:var(--muted)]">
          <span className="text-[color:var(--ink)] [font-family:var(--mono)]">{device.hostname}</span>
          <span aria-hidden="true">·</span><span>{device.vendor}{device.os ? ` ${device.os}` : ""}</span>
          {finding.blast_radius?.length ? <><span aria-hidden="true">·</span><span>{finding.blast_radius.length} dependent device{finding.blast_radius.length === 1 ? "" : "s"}</span></> : null}
        </p>
      </header>

      <section className="border-b border-[color:var(--line)] px-4 py-3">
        <h4 className="m-0 mb-2 text-[11px] font-semibold uppercase tracking-[0.06em] text-[color:var(--muted)]">Violation</h4>
        {lines.length ? (
          <ol className="m-0 list-none overflow-x-auto rounded-sm border border-[color:var(--line-soft)] bg-[color:var(--well)] py-1 text-[12px] leading-5 [font-family:var(--mono)]">
            {lines.map((l) => (
              <li key={l.line} className={`flex whitespace-pre ${sev.line}`}>
                <span className="w-12 shrink-0 select-none pr-3 text-right text-[color:var(--muted)] tabular-nums">{l.line}</span>
                <span>{l.text}</span>
              </li>
            ))}
          </ol>
        ) : null}
        <p className="m-0 mt-2 text-[12px] text-[color:var(--muted)]">{finding.evidence}</p>
      </section>

      <section className="border-b border-[color:var(--line)]">
        <div className="flex flex-wrap items-center gap-2 px-4 pb-2 pt-3">
          <h4 className="m-0 text-[11px] font-semibold uppercase tracking-[0.06em] text-[color:var(--muted)]">{isDraft ? "Proposed fix · AI draft" : "Fix"}</h4>
          <span className={`rounded-sm border px-1.5 py-px text-[11px] [font-family:var(--mono)] ${isDraft ? "border-[color:var(--warning-border)] bg-[color:var(--warning-bg)] text-[color:var(--warning-fg)]" : "border-[color:var(--line)] text-[color:var(--muted)]"}`}>
            {isDraft ? "unverified · agentic_rag" : remediation.template_name}
          </span>
          <button type="button" onClick={copy} className="ml-auto rounded-sm border border-[color:var(--line)] bg-[color:var(--panel2)] px-2 py-0.5 text-[11px] font-medium text-[color:var(--ink)] hover:border-[color:var(--line-strong)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[color:var(--teal)]">
            {copied === "done" ? "Copied" : copied === "failed" ? "Select and copy manually" : "Copy script"}
          </button>
        </div>
        <Script text={remediation.script} />
        {state.flags.length > 0 && (
          <ul className="m-0 grid list-none gap-1 border-t border-[color:var(--warning-border)] bg-[color:var(--warning-bg)] px-4 py-2 text-[12px] text-[color:var(--warning-fg)]">
            {state.flags.map((f) => <li key={f} className="[font-family:var(--mono)]">{f}</li>)}
          </ul>
        )}
        {remediation.rollback_script && (
          <details className="group border-t border-[color:var(--line)]">
            <summary className="cursor-pointer list-none px-4 py-2 text-[12px] text-[color:var(--muted)] hover:text-[color:var(--ink)]">
              <span className="inline-block transition-transform group-open:rotate-90" aria-hidden="true">›</span> Rollback script · restores the pre-fix state
            </summary>
            <Script text={remediation.rollback_script} />
          </details>
        )}
      </section>

      <dl className="m-0 grid grid-cols-[repeat(auto-fit,minmax(9.5rem,1fr))] gap-px border-b border-[color:var(--line)] bg-[color:var(--line-soft)]">
        {state.gates.map((g) => (
          <div key={g.label} className="flex min-w-0 items-start gap-1.5 bg-[color:var(--panel)] px-3 py-2">
            <GateIcon tone={g.tone} />
            <div className="min-w-0">
              <dt className="text-[11px] text-[color:var(--muted)]">{g.label}</dt>
              <dd className={`m-0 truncate text-[12px] ${g.tone === "fail" ? "text-[color:var(--critical)]" : "text-[color:var(--ink)]"}`} title={g.detail}>{g.detail}</dd>
            </div>
          </div>
        ))}
      </dl>

      <footer className="flex flex-wrap items-center gap-3 px-4 py-3">
        <p className="m-0 min-w-0 flex-1 basis-56 text-[12px] text-[color:var(--muted)]" aria-live="polite">{state.note}</p>
        {(state.kind === "approve" || (isDraft && remediation.approval_status === "PENDING")) && (
          <button type="button" disabled={busy} onClick={onReject} className="rounded-sm border border-[color:var(--line)] bg-[color:var(--panel2)] px-3.5 py-2 text-[12px] font-semibold text-[color:var(--ink)] hover:border-[color:var(--line-strong)] disabled:cursor-not-allowed disabled:opacity-45 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[color:var(--teal)]">
            Reject
          </button>
        )}
        <button type="button" disabled={busy || !state.enabled} onClick={primary} aria-expanded={state.kind === "rollback" ? rollbackOpen : undefined}
          className={`rounded-sm px-4 py-2 text-[12px] font-semibold disabled:cursor-not-allowed focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[color:var(--teal)] ${state.kind === "rollback"
            ? "border border-[color:var(--line-strong)] bg-transparent text-[color:var(--ink)] hover:bg-[color:var(--panel2)]"
            : "bg-[color:var(--teal)] text-[color:var(--teal-ink)] [box-shadow:var(--shadow-sm)] hover:bg-[color:var(--teal-hover)] disabled:bg-[color:var(--panel2)] disabled:text-[color:var(--muted)] disabled:[box-shadow:none]"}`}>
          {busy ? "Working…" : state.label}
        </button>
      </footer>

      {rollbackOpen && state.kind === "rollback" && (
        <form className="flex flex-wrap items-end gap-2 border-t border-[color:var(--line)] px-4 py-3" onSubmit={(e) => { e.preventDefault(); onRollback(reason.trim()); setRollbackOpen(false); setReason(""); }}>
          <label className="grid min-w-0 flex-1 basis-64 gap-1 text-[11px] text-[color:var(--muted)]">
            Reason for rollback
            <input id={`rac-rollback-${finding.control_id}`} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. broke management access from the NOC jump host"
              className="rounded-sm border border-[color:var(--line)] bg-[color:var(--well)] px-2.5 py-2 text-[13px] text-[color:var(--ink)] placeholder:text-[color:var(--muted)] focus:border-[color:var(--teal)] focus:outline-none" />
          </label>
          <button type="submit" disabled={busy || !reason.trim()} className="rounded-sm bg-[color:var(--teal)] px-4 py-2 text-[12px] font-semibold text-[color:var(--teal-ink)] disabled:cursor-not-allowed disabled:opacity-45">Confirm rollback</button>
        </form>
      )}
    </article>
  );
}
