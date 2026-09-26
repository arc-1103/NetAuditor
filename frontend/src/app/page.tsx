"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  applyRemediation, approveRemediation, askLocalQwen, generateRemediations, generateReport, getAudit,
  getAuditTrust, getExecutiveReport, getLearningQueue, getProvenance, login, openProtectedReport,
  rollbackRemediation, Role, submitLearningMap, uploadConfig, USE_MOCK,
} from "../lib/api";
import type { AuditRun, ExecutiveReport, Finding, LearningQueueItem, ProvenanceChain, Remediation, Severity, TrustView } from "../lib/types";

const severityOrder: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const ROLES: Role[] = ["admin", "operator", "auditor"];

function Login({ onLogin }: { onLogin: (token: string, email: string, role: Role) => void }) {
  const [email, setEmail] = useState("admin@netaudit.local");
  const [password, setPassword] = useState("changeme");
  const [role, setRole] = useState<Role>("admin");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError("");
    try { const result = await login(email, password, role); onLogin(result.access_token, result.user.email, result.user.role); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Login failed"); }
    finally { setBusy(false); }
  }
  return <main className="login-shell">
    <section className="login-story">
      <div className="brand"><span className="brand-mark">N</span><span>NETAUDIT</span></div>
      <div className="story-copy">
        <p className="eyebrow">SIH 26155 · NTRO</p>
        <h1>See the risk.<br /><em>Prove</em> the fix.</h1>
        <p>Air-gapped, explainable network security compliance across heterogeneous device configurations.</p>
        <div className="trust-row"><span>LOCAL AI</span><span>OPA VERIFIED</span><span>HUMAN APPROVED</span></div>
      </div>
    </section>
    <section className="login-panel">
      <form className="login-card" onSubmit={submit}>
        <p className="eyebrow">SECURE OPERATIONS CONSOLE</p><h2>Welcome back</h2>
        <p className="muted">Sign in to review your network security posture.</p>
        <label>Email<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required /></label>
        <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
        {USE_MOCK && <label>Role (demo only — a real login gets its role from the server)
          <div className="role-picker">{ROLES.map((r) => <button type="button" key={r} className={role === r ? "active" : ""} onClick={() => setRole(r)}>{r}</button>)}</div>
        </label>}
        {error && <div className="alert error">{error}</div>}
        <button className="primary wide" disabled={busy}>{busy ? "Authenticating…" : "Enter console"}</button>
        {USE_MOCK && <p className="demo-note">Presentation fallback is active · deterministic local data</p>}
      </form>
    </section>
  </main>;
}

function ConfidenceLedger({ device }: { device?: AuditRun["device"] }) {
  const logprob = device?.mean_logprob;
  const fidelity = device?.reverse_translation_fidelity;
  const logprobLabel = logprob == null ? null : logprob >= -0.3 ? "High" : logprob >= -0.5 ? "Borderline" : "Low";
  return <section className="confidence-ledger">
    <div className="cl-title"><p className="eyebrow">CONFIDENCE LEDGER</p><span>What the model itself thinks of this extraction — shown, not hidden behind a verdict.</span></div>
    <div className="cl-row">
      <div className="cl-item">
        <p>Mean token confidence</p>
        {logprob == null ? <span className="cl-note">Not measured this run (mock mode or no logprob signal).</span> : <>
          <strong>{logprob.toFixed(3)}</strong>
          <span className={`cl-badge ${logprobLabel?.toLowerCase()}`}>{logprobLabel}</span>
          <span className="cl-note">Below −0.5 routes the chunk to human review instead of a silent guess.</span>
        </>}
      </div>
      <div className="cl-item">
        <p>Reverse-translation fidelity</p>
        {fidelity == null ? <span className="cl-note">Not measured this run (reverse translation disabled or unavailable).</span> : <>
          <strong>{Math.round(fidelity * 100)}%</strong>
          <span className="cl-note">A second model call reconstructs CLI from the parsed JSON and is diffed against the original — below 70% routes to human review.</span>
        </>}
      </div>
    </div>
  </section>;
}

function TrustPanel({ runId, token }: { runId: string; token: string }) {
  const [trust, setTrust] = useState<TrustView | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  async function load() {
    setLoading(true); setError("");
    try { setTrust(await getAuditTrust(runId, token)); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Could not load the trust ledger"); }
    finally { setLoading(false); }
  }
  if (!trust) return <section className="confidence-ledger">
    <div className="cl-title"><p className="eyebrow">AI TRUST LAYER</p><span>Per-field agreement between the SLM's extraction and the deterministic TextFSM cross-check.</span></div>
    {error && <div className="alert error">{error}</div>}
    <button className="secondary" onClick={load} disabled={loading}>{loading ? "Loading…" : "Load field-by-field agreement"}</button>
  </section>;
  return <section className="confidence-ledger">
    <div className="cl-title"><p className="eyebrow">AI TRUST LAYER</p><span>{trust.fields_compared} field{trust.fields_compared === 1 ? "" : "s"} the deterministic cross-check could verify.</span></div>
    {trust.fields.length === 0 ? <p className="muted">This vendor isn't covered by the deterministic cross-check yet — no independent second opinion exists for this baseline.</p> : <div>
      <div className="trust-row-item"><span className="source" style={{ fontWeight: 700 }}>Field</span><span className="source" style={{ fontWeight: 700 }}>SLM said</span><span className="source" style={{ fontWeight: 700 }}>Deterministic said</span><span className="source" style={{ fontWeight: 700 }}>Agree?</span></div>
      {trust.fields.map((f) => <div className="trust-row-item" key={f.field}>
        <code>{f.field}</code><code>{JSON.stringify(f.slm_value)}</code><code>{JSON.stringify(f.deterministic_value)}</code>
        <span className={`agree-flag ${f.agree ? "yes" : "no"}`}>{f.agree ? "AGREE" : "DIFFER"}</span>
      </div>)}
    </div>}
  </section>;
}

function ScoreRing({ value }: { value: number }) {
  const color = value >= 80 ? "#47d7ac" : value >= 50 ? "#f6c85f" : "#ff6b6b";
  return <div className="score-ring" style={{ background: `conic-gradient(${color} ${value * 3.6}deg, #23364a 0deg)` }}>
    <div><strong>{value}</strong><span>/100</span></div>
  </div>;
}

function EvidenceLines({ finding }: { finding: Finding }) {
  if (!finding.source_lines?.length) return <p className="source">The issue was inferred from the normalized configuration.</p>;
  return <div className="source-lines">{finding.source_lines.map((item, index) => {
    const line = typeof item === "number" ? item : item.line;
    const content = typeof item === "number" ? "Supporting configuration line" : item.text;
    return <div key={`${line}-${index}`}><span>LINE {line}</span><code>{content}</code></div>;
  })}</div>;
}

function ProvenancePanel({ runId, controlId, token }: { runId: string; controlId: string; token: string }) {
  const [chain, setChain] = useState<ProvenanceChain | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  async function load() {
    setLoading(true); setError("");
    try { setChain(await getProvenance(runId, controlId, token)); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Could not load the provenance chain"); }
    finally { setLoading(false); }
  }
  if (!chain) return <section>
    <h3>Provenance</h3>
    {error && <div className="alert error">{error}</div>}
    <button className="secondary" onClick={load} disabled={loading}>{loading ? "Loading…" : "View full provenance chain"}</button>
  </section>;
  return <section>
    <h3>Provenance</h3>
    {chain.events.length === 0 ? <p className="muted">No ledger events recorded yet for this control.</p> : chain.events.map((event, index) => <div className="chain-step" key={index}>
      <span>{event.event_type}</span>
      <span>{event.actor} · {new Date(event.created_at).toLocaleString()}{event.ruleset_version ? ` · ruleset ${event.ruleset_version}` : ""}</span>
    </div>)}
    {chain.policy && <p className="source">Evaluated against policy bundle <b>{String(chain.policy.policy_bundle_version)}</b>, baseline SHA-256 {String(chain.policy.baseline_sha256).slice(0, 16)}…</p>}
  </section>;
}

function FindingPanel({ finding, remediation, onDecision, onApply, onRollback, busy, runId, token, role }: {
  finding: Finding; remediation?: Remediation;
  onDecision: (approved: boolean) => void;
  onApply: () => void;
  onRollback: (reason: string) => void;
  busy: boolean; runId: string; token: string; role: Role;
}) {
  const status = remediation?.preflight_status || remediation?.preflight?.status;
  const flags = remediation?.risk_flags || remediation?.preflight?.risk_flags || [];
  const [qwenAnswer, setQwenAnswer] = useState("");
  const [qwenStatus, setQwenStatus] = useState("");
  const [rollbackReason, setRollbackReason] = useState("");
  const [showRollbackForm, setShowRollbackForm] = useState(false);
  async function explain() {
    setQwenStatus("asking"); setQwenAnswer("");
    try { setQwenAnswer(await askLocalQwen(finding.title, finding.evidence)); setQwenStatus("ready"); }
    catch { setQwenStatus("error"); }
  }
  const isDualApproval = remediation?.decision?.action === "DUAL_APPROVAL";
  // Mirrors app/approval_matrix.py's check_permission so a disabled button
  // never surprises the operator with a 403 the UI could have predicted.
  const roleBlocksApproval = role === "auditor"
    || (role === "operator" && remediation?.decision && (remediation.decision.risk === "HIGH" || remediation.decision.blast_radius_count > 0));
  const isApplied = remediation?.applied_at != null;
  const isRolledBack = remediation?.rollback_status === "ROLLED_BACK";
  return <aside className="drawer">
    <div className="drawer-head"><div><span className={`severity ${finding.severity.toLowerCase()}`}>{finding.severity}</span><p>{finding.control_id} · {finding.framework}</p></div></div>
    <h2>{finding.title}</h2>
    <section><h3>What we found</h3><pre className="evidence">{finding.evidence}</pre><EvidenceLines finding={finding} /></section>
    <section><h3>Why this matters</h3><p className="muted">In simple terms, this setting may let an attacker reach or control the device more easily. A person must review every suggested fix before approval.</p>{finding.blast_radius?.length ? <p className="blast">Other devices that may be affected · {finding.blast_radius.join(" · ")}</p> : null}</section>
    <section className="qwen-box"><div className="remediation-title"><h3>Live local AI</h3><span className={`model-state ${qwenStatus}`}>{qwenStatus === "ready" ? "QWEN LIVE" : "OPTIONAL"}</span></div><p className="muted">Ask locally running Qwen to explain this result in everyday language. It explains; fixed rules still decide.</p><button className="secondary" onClick={explain} disabled={qwenStatus === "asking"}>{qwenStatus === "asking" ? "Qwen is thinking…" : "Ask Qwen to explain"}</button>{qwenAnswer && <p className="ai-answer">{qwenAnswer}</p>}{qwenStatus === "error" && <p className="source">Local model unavailable. Run: ollama serve</p>}</section>
    {!remediation ? <div className="empty-card"><p>No proposal generated yet.</p><span>Generate deterministic fixes for this audit from the toolbar.</span></div> : <section>
      <div className="remediation-title"><h3>Proposed remediation</h3><span className={`preflight ${(status || "unavailable").toLowerCase()}`}>{status || "UNKNOWN"}</span></div>
      {remediation.source === "agentic_rag" && <div className="alert error">AI-synthesized draft · cannot be directly approved</div>}
      {flags.length > 0 && <div className="alert warning">{flags.join(" · ")}</div>}
      {isDualApproval && !isApplied && <p className="source">
        <span className="badge dual">2-person rule</span>{" "}
        {remediation.dual_approval ? `${remediation.dual_approval.received} of ${remediation.dual_approval.required} approvals recorded` : "requires two independent approvals"}
      </p>}
      {roleBlocksApproval && remediation.approval_status !== "APPROVED" && <p className="source">Your role ({role}) cannot approve this change — see docs/Additional-Features.md §7's approval matrix.</p>}
      <pre className="command">{remediation.script}</pre>
      {!isApplied ? <div className="decision-row">
        <button className="secondary" disabled={busy} onClick={() => onDecision(false)}>Reject</button>
        <button className="primary" disabled={busy || status !== "SAFE" || roleBlocksApproval} onClick={() => onDecision(true)}>{remediation.approval_status === "APPROVED" ? "Approved ✓" : "Approve safe fix"}</button>
      </div> : null}
      {remediation.approval_status === "APPROVED" && !isApplied && <div className="decision-row">
        <span className="source">Approved — an operator can now run this script and mark it applied.</span>
        <button className="primary" disabled={busy} onClick={onApply}>Mark applied</button>
      </div>}
      {isApplied && !isRolledBack && <div className="decision-row">
        <span className="badge applied">APPLIED · {new Date(remediation.applied_at as string).toLocaleString()}</span>
        <button className="secondary" disabled={busy} onClick={() => setShowRollbackForm((v) => !v)}>Roll back</button>
      </div>}
      {isApplied && !isRolledBack && showRollbackForm && <div className="teach-form">
        <label>Reason for rollback<input value={rollbackReason} onChange={(e) => setRollbackReason(e.target.value)} placeholder="e.g. broke management access to branch switch" /></label>
        <div className="decision-row"><button className="primary" disabled={busy || !rollbackReason.trim()} onClick={() => { onRollback(rollbackReason); setShowRollbackForm(false); setRollbackReason(""); }}>Confirm rollback</button></div>
      </div>}
      {isRolledBack && <p className="source"><span className="badge rolled-back">ROLLED BACK</span></p>}
    </section>}
    <ProvenancePanel runId={runId} controlId={finding.control_id} token={token} />
  </aside>;
}

function TeachForm({ item, token, onTaught }: { item: LearningQueueItem; token: string; onTaught: (blockId: string) => void }) {
  const [open, setOpen] = useState(false);
  const [cliPattern, setCliPattern] = useState("");
  const [field, setField] = useState("");
  const [value, setValue] = useState("");
  const [vendor, setVendor] = useState("");
  const [os, setOs] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit() {
    setBusy(true); setError("");
    try {
      await submitLearningMap({ block_id: item.block_id, cli_pattern: cliPattern, field, value, vendor: vendor || undefined, os: os || null }, token);
      onTaught(item.block_id);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Could not save this mapping"); }
    finally { setBusy(false); }
  }
  if (!open) return <div className="decision-row"><span /><button className="secondary" onClick={() => setOpen(true)}>Teach this block</button></div>;
  return <div className="teach-form">
    <label>CLI pattern (the line that wasn't recognized)<input value={cliPattern} onChange={(e) => setCliPattern(e.target.value)} placeholder={item.raw_text.split("\n")[0] || "e.g. set security zone trust"} /></label>
    <label>Security field this maps to<input value={field} onChange={(e) => setField(e.target.value)} placeholder="e.g. ssh.management_acl" /></label>
    <label>Value<input value={value} onChange={(e) => setValue(e.target.value)} placeholder="e.g. MGMT-ONLY" /></label>
    <label>Vendor (optional)<input value={vendor} onChange={(e) => setVendor(e.target.value)} placeholder="e.g. juniper" /></label>
    <label>OS (optional)<input value={os} onChange={(e) => setOs(e.target.value)} placeholder="e.g. junos" /></label>
    {error && <div className="alert error">{error}</div>}
    <div className="decision-row"><button className="secondary" onClick={() => setOpen(false)} disabled={busy}>Cancel</button><button className="primary" disabled={busy || !cliPattern.trim() || !field.trim() || !value.trim()} onClick={submit}>{busy ? "Saving…" : "Confirm mapping"}</button></div>
  </div>;
}

function LearningQueue({ token }: { token: string }) {
  const [items, setItems] = useState<LearningQueueItem[] | null>(null);
  const [loadError, setLoadError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [notice, setNotice] = useState("");
  useEffect(() => {
    setItems(null); setLoadError("");
    getLearningQueue(token).then(setItems).catch(() => setLoadError("offline"));
  }, [token, attempt]);
  function onTaught(blockId: string) {
    setItems((prev) => (prev || []).filter((item) => item.block_id !== blockId));
    setNotice("Mapping saved — the model will use it for future configs from this vendor/OS.");
  }
  return <div className="workspace"><header><div><p className="eyebrow">SECURITY OPERATIONS</p><h1>Learning queue</h1></div></header>
    {notice && <div className="alert success">{notice}<button onClick={() => setNotice("")}>×</button></div>}
    {loadError && <div className="empty-card">
      <p>Learning service is offline</p>
      <span>This optional service queues configuration blocks the model couldn&apos;t recognize, so a human can teach it new syntax. It isn&apos;t part of the core audit path — findings and reports work without it.</span>
      <div className="decision-row"><button className="secondary" onClick={() => setAttempt((n) => n + 1)}>Retry</button></div>
    </div>}
    {!loadError && items === null && <p className="muted">Loading queue…</p>}
    {!loadError && items?.length === 0 && <p className="muted">No unrecognized configuration blocks are waiting for review.</p>}
    {!loadError && items && items.length > 0 && <div className="finding-list">{items.map((item) => <div key={item.block_id} className="empty-card" style={{ textAlign: "left" }}>
      <p>Unrecognized configuration block</p><span style={{ display: "block", marginBottom: 8 }}>{item.raw_text}</span>
      <TeachForm item={item} token={token} onTaught={onTaught} />
    </div>)}</div>}
  </div>;
}

function DeviceInventory({ inventory, onSelect }: { inventory: AuditRun[]; onSelect: (run: AuditRun) => void }) {
  return <div className="workspace"><header><div><p className="eyebrow">SECURITY OPERATIONS</p><h1>Device inventory</h1></div></header>
    {inventory.length === 0 ? <p className="muted">No device has been audited yet this session. Upload a configuration from Audit workspace first.</p> : <div className="finding-list">{inventory.map((run) => <button key={run.id} onClick={() => onSelect(run)} style={{ gridTemplateColumns: "1fr auto" }}>
      <div><strong>{run.original_filename}</strong><p>Vendor {run.device?.detected_vendor || "Detected"} · OS {run.device?.detected_os || "Unknown"} · Parse confidence {Math.round((run.device?.parsing_confidence || 0) * 100)}% · SHA-256 {run.file_hash.slice(0, 16)}…</p></div>
      <span className="finding-state">{run.summary?.total_findings ?? 0} findings</span>
    </button>)}</div>}
  </div>;
}

function ReportsView({ audit, token }: { audit: AuditRun | null; token: string }) {
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  async function openKind(kind: "download" | "json" | "cef") {
    if (!audit) return;
    setBusy(kind); setError("");
    try {
      if (kind === "download") {
        await generateReport(audit.id, token);
      } else if (USE_MOCK) {
        // generateReport's own mock branch already does this for
        // "download" — json/cef need the same client-side fallback rather
        // than silently doing nothing when there's no live backend to ask.
        if (kind === "json") {
          const report = { product: "NetAudit", mode: "deterministic presentation fallback", audit_run: audit.id, summary: audit.summary, findings: audit.findings };
          const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
          window.open(url, "_blank", "noopener,noreferrer");
          window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
        } else {
          throw new Error("CEF export needs a live backend — not available in demo mode");
        }
      } else {
        await openProtectedReport(audit.id, token, kind);
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The report could not be opened");
    } finally {
      setBusy("");
    }
  }
  return <div className="workspace"><header><div><p className="eyebrow">SECURITY OPERATIONS</p><h1>Reports</h1></div></header>
    {!audit ? <p className="muted">No audit report is available yet. Generate one from Audit workspace after uploading a configuration.</p> : <div className="empty-card">
      <p>{audit.original_filename} · {audit.id}</p>
      {error && <div className="alert error">{error}</div>}
      <div className="decision-row">
        <button className="secondary" disabled={!!busy} onClick={() => openKind("download")}>{busy === "download" ? "Building…" : "Download PDF"}</button>
        <button className="secondary" disabled={!!busy} onClick={() => openKind("json")}>{busy === "json" ? "Loading…" : "View JSON"}</button>
        <button className="secondary" disabled={!!busy} onClick={() => openKind("cef")}>{busy === "cef" ? "Loading…" : "View CEF"}</button>
      </div>
    </div>}
  </div>;
}

function ExecutiveReportView({ token }: { token: string }) {
  const [report, setReport] = useState<ExecutiveReport | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    getExecutiveReport(token).then(setReport).catch((reason) => setError(reason instanceof Error ? reason.message : "Could not load the executive report"));
  }, [token]);
  return <div className="workspace"><header><div><p className="eyebrow">SECURITY OPERATIONS</p><h1>Executive report</h1></div></header>
    {error && <div className="alert error">{error}</div>}
    {!report ? <p className="muted">Loading fleet-wide compliance posture…</p> : <>
      <section className="exec-grid">
        <div className="exec-card">
          <h3>Fleet score</h3>
          <div className="score-card" style={{ border: 0, padding: 0 }}>
            <ScoreRing value={report.fleet_score.fleet_score} />
            <div><p>Across evaluated devices</p><strong>{report.fleet_score.devices_scored} device{report.fleet_score.devices_scored === 1 ? "" : "s"} scored</strong></div>
          </div>
        </div>
        <div className="exec-card">
          <h3>Trend</h3>
          {report.fleet_score_trend.length === 0 ? <p className="muted">Not enough history yet.</p> : <table className="mini-table"><tbody>
            {report.fleet_score_trend.map((point, i) => <tr key={i}><td>{new Date(point.evaluated_at).toLocaleDateString()}</td><td>{point.fleet_score}/100</td></tr>)}
          </tbody></table>}
        </div>
      </section>

      <div className="stat-row">
        <div className="stat-tile"><p>Violations found</p><strong>{report.violations.found}</strong></div>
        <div className="stat-tile"><p>Resolved</p><strong>{report.violations.resolved}</strong></div>
        <div className="stat-tile"><p>Still open</p><strong>{report.violations.still_open}</strong></div>
        <div className="stat-tile"><p>Over SLA</p><strong>{report.mttr.open_violations_over_sla}</strong></div>
      </div>

      <section className="exec-grid">
        <div className="exec-card">
          <h3>Top exposed devices</h3>
          {report.top_exposed_devices.length === 0 ? <p className="muted">No evaluated devices yet.</p> : <table className="mini-table"><thead><tr><th>Device</th><th>Vendor</th><th>Score</th><th>Findings</th></tr></thead><tbody>
            {report.top_exposed_devices.map((d) => <tr key={d.audit_run_id}><td>{d.original_filename || d.audit_run_id.slice(0, 8)}</td><td>{d.detected_vendor || "—"}</td><td>{d.compliance_score}/100</td><td>{d.total_findings}</td></tr>)}
          </tbody></table>}
        </div>
        <div className="exec-card">
          <h3>Remediation action mix</h3>
          <table className="mini-table"><tbody>
            <tr><td>Auto-applied</td><td>{report.remediation_action_mix.auto_applied}</td></tr>
            <tr><td>Human-approved</td><td>{report.remediation_action_mix.human_approved}</td></tr>
            <tr><td>Blocked</td><td>{report.remediation_action_mix.blocked}</td></tr>
            <tr><td>Rejected</td><td>{report.remediation_action_mix.rejected}</td></tr>
            <tr><td>Pending</td><td>{report.remediation_action_mix.pending}</td></tr>
          </tbody></table>
        </div>
      </section>

      <div className="exec-card">
        <h3>Mean time to remediate, by severity</h3>
        <table className="mini-table"><thead><tr><th>Severity</th><th>Avg MTTR</th><th>Target</th><th>Sample</th></tr></thead><tbody>
          {severityOrder.map((level) => { const row = report.mttr.by_severity[level]; return <tr key={level}>
            <td><span className={`severity ${level.toLowerCase()}`}>{level}</span></td>
            <td>{row.avg_mttr_seconds == null ? "—" : `${(row.avg_mttr_seconds / 3600).toFixed(1)}h`}</td>
            <td>{(row.target_seconds / 3600).toFixed(0)}h</td>
            <td>{row.sample_size}</td>
          </tr>; })}
        </tbody></table>
      </div>
    </>}
  </div>;
}

// Session state only lives in React memory by default, so a refresh (or the
// browser reclaiming the tab) silently drops the logged-in session and the
// audit just reviewed. sessionStorage survives both and clears itself when
// the tab actually closes, which matches "this session" without persisting
// across separate visits the way localStorage would.
function readSession<T>(key: string, fallback: T): T {
  if (typeof window === "undefined") return fallback;
  try {
    const raw = window.sessionStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}
function writeSession(key: string, value: unknown) {
  try { window.sessionStorage.setItem(key, JSON.stringify(value)); } catch { /* private mode, storage full, etc. */ }
}

// Device inventory is a history, not session state — it must survive a
// closed tab or a fresh login the way sessionStorage above deliberately
// doesn't, so it lives in localStorage instead.
function readLocal<T>(key: string, fallback: T): T {
  if (typeof window === "undefined") return fallback;
  try {
    const raw = window.localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}
function writeLocal(key: string, value: unknown) {
  try { window.localStorage.setItem(key, JSON.stringify(value)); } catch { /* private mode, storage full, etc. */ }
}

export default function Home() {
  // Every persisted field below starts at its SSR-safe fallback and is
  // only replaced with the real sessionStorage/localStorage value inside
  // the hydration effect further down — reading storage during the
  // useState initializer itself (the previous pattern here) runs during
  // the client's first render, which the server can't match (it has no
  // storage to read), producing a hydration-mismatch error and a
  // regenerated tree on every reload while logged in.
  const [token, setToken] = useState(""); const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("admin");
  const [audit, setAudit] = useState<AuditRun | null>(null); const [selected, setSelected] = useState<Finding | null>(null);
  const [inventory, setInventory] = useState<AuditRun[]>([]);
  const [remediations, setRemediations] = useState<Remediation[]>([]); const [busy, setBusy] = useState("");
  const [notice, setNotice] = useState(""); const [error, setError] = useState(""); const [dragging, setDragging] = useState(false);
  const [view, setView] = useState<"workspace" | "inventory" | "learning" | "reports" | "executive">("workspace");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [hydrated, setHydrated] = useState(false);
  useEffect(() => {
    setToken(readSession("na_token", "")); setEmail(readSession("na_email", ""));
    setRole(readSession("na_role", "admin" as Role));
    setAudit(readSession("na_audit", null));
    setInventory(readLocal("na_inventory", []));
    setRemediations(readSession("na_remediations", []));
    setSidebarCollapsed(readSession("na_sidebar_collapsed", false));
    setHydrated(true);
  }, []);
  // Guarded by `hydrated` so the fallback values above never overwrite the
  // real persisted state with blanks before the hydration effect runs.
  useEffect(() => { if (hydrated) writeLocal("na_inventory", inventory); }, [inventory, hydrated]);
  useEffect(() => { if (hydrated) writeSession("na_sidebar_collapsed", sidebarCollapsed); }, [sidebarCollapsed, hydrated]);
  useEffect(() => { if (hydrated) { writeSession("na_token", token); writeSession("na_email", email); } }, [token, email, hydrated]);
  useEffect(() => { if (hydrated) { writeSession("na_audit", audit); if (audit) setSelected((current) => current || audit.findings[0] || null); } }, [audit, hydrated]);
  useEffect(() => { if (hydrated) writeSession("na_remediations", remediations); }, [remediations, hydrated]);
  useEffect(() => { if (hydrated) writeSession("na_role", role); }, [role, hydrated]);
  const selectedRemediation = useMemo(() => remediations.find((item) => item.control_id === selected?.control_id), [remediations, selected]);

  async function handleFile(file?: File) {
    if (!file) return;
    const extension = file.name.slice(file.name.lastIndexOf(".")).toLowerCase();
    if (![".cfg", ".conf", ".txt"].includes(extension)) { setError("Choose a .cfg, .conf or .txt configuration file."); return; }
    if (file.size > 10 * 1024 * 1024) { setError("Configuration files must be 10 MB or smaller."); return; }
    setBusy("upload"); setError(""); setNotice("Configuration accepted. Parsing and deterministic policy evaluation are running…");
    try {
      const uploaded = await uploadConfig(file, token);
      const run = await getAudit(uploaded.job_id, token);
      const completed = { ...run, original_filename: USE_MOCK ? file.name : run.original_filename };
      setAudit(completed);
      setSelected(run.findings[0] || null);
      setInventory((prev) => [completed, ...prev.filter((item) => item.id !== completed.id)]);
      setNotice(run.status === "NEEDS_REVIEW" ? "No compliance verdict was issued: parsing evidence requires human review." : "Audit completed. Every verdict below was produced by version-controlled policy.");
    }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Upload failed"); }
    finally { setBusy(""); }
  }
  function newAudit() {
    setAudit(null); setSelected(null); setRemediations([]); setError(""); setNotice(""); setBusy("");
  }
  function openFromInventory(run: AuditRun) {
    setAudit(run); setSelected(run.findings[0] || null); setRemediations([]); setError(""); setNotice(""); setView("workspace");
  }
  async function remediationAction() {
    if (!audit) return; setBusy("remediation"); setError("");
    try { setRemediations(await generateRemediations(audit.id, token)); setNotice("Remediation proposals generated and preflighted. Only SAFE proposals can be approved."); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Generation failed"); }
    finally { setBusy(""); }
  }
  async function decide(approved: boolean) {
    if (!audit || !selected) return; setBusy("decision"); setError("");
    try {
      const result = await approveRemediation(selected.control_id, audit.id, approved, token, role, email);
      setRemediations((items) => items.map((item) => item.control_id === selected.control_id ? { ...item, approval_status: result.approval_status, dual_approval: result.dual_approval ?? item.dual_approval } : item));
      setNotice(
        result.approval_status === "PENDING" ? `Recorded — ${result.dual_approval?.received ?? 1} of ${result.dual_approval?.required ?? 2} approvals in. A second, distinct approver is still required.`
          : approved ? "Safe remediation approved with operator attribution." : "Proposal rejected and retained in the audit trail.",
      );
    }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Decision failed"); }
    finally { setBusy(""); }
  }
  async function applyFix() {
    if (!audit || !selected) return; setBusy("decision"); setError("");
    try {
      const result = await applyRemediation(selected.control_id, audit.id, token);
      setRemediations((items) => items.map((item) => item.control_id === selected.control_id ? { ...item, applied_at: result.applied_at, rollback_status: result.rollback_status, pre_change_baseline_sha256: result.pre_change_baseline_sha256 } : item));
      setNotice("Marked applied — an operator has confirmed this script was run on the device.");
    }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Could not mark this proposal applied"); }
    finally { setBusy(""); }
  }
  async function rollbackFix(reason: string) {
    if (!audit || !selected) return; setBusy("decision"); setError("");
    try {
      const result = await rollbackRemediation(selected.control_id, audit.id, reason, token);
      setRemediations((items) => items.map((item) => item.control_id === selected.control_id ? { ...item, rollback_status: result.rollback_status } : item));
      setNotice("Rollback recorded in the audit trail.");
    }
    catch (reason2) { setError(reason2 instanceof Error ? reason2.message : "Rollback failed"); }
    finally { setBusy(""); }
  }
  async function report() {
    if (!audit) return; setBusy("report"); setError("");
    try { await generateReport(audit.id, token); setNotice(USE_MOCK ? "Report generated. Real deployment provides PDF, JSON and CEF downloads." : "Evidence report generated and ready to download."); if (!USE_MOCK) await openProtectedReport(audit.id, token, "preview"); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Report generation failed"); }
    finally { setBusy(""); }
  }

  if (!token) return <Login onLogin={(newToken, userEmail, userRole) => { setToken(newToken); setEmail(userEmail); setRole(userRole); }} />;
  return <main className={`app-shell ${sidebarCollapsed ? "sidebar-collapsed" : ""}`}>
    <nav className="sidebar"><div className="sidebar-head"><div className="brand"><span className="brand-mark">N</span><span>NETAUDIT</span></div><button className="sidebar-toggle" onClick={() => setSidebarCollapsed((c) => !c)} aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"} title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}>{sidebarCollapsed ? "»" : "«"}</button></div><div className="nav-items"><button className={view === "workspace" ? "active" : ""} onClick={() => setView("workspace")}>⌁<span>Audit workspace</span></button><button className={view === "inventory" ? "active" : ""} onClick={() => setView("inventory")}>▦<span>Device inventory</span></button><button className={view === "learning" ? "active" : ""} onClick={() => setView("learning")}>◎<span>Learning queue</span></button><button className={view === "reports" ? "active" : ""} onClick={() => setView("reports")}>◫<span>Reports</span></button><button className={view === "executive" ? "active" : ""} onClick={() => setView("executive")}>◆<span>Executive report</span></button></div><div className="method-card"><span className="pulse" /><strong>Decision boundary active</strong><p>AI extracts. OPA decides.</p></div><div className="user"><span>{email.slice(0, 1).toUpperCase()}</span><div><strong>{email}</strong><small>{role.charAt(0).toUpperCase() + role.slice(1)}</small></div></div></nav>
    {view === "inventory" ? <DeviceInventory inventory={inventory} onSelect={openFromInventory} /> : view === "learning" ? <LearningQueue token={token} /> : view === "reports" ? <ReportsView audit={audit} token={token} /> : view === "executive" ? <ExecutiveReportView token={token} /> :
      <div className="workspace"><header><div><p className="eyebrow">SECURITY OPERATIONS</p><h1>Audit workspace</h1></div><div className="header-actions"><span className="airgap">● WORKS WITHOUT INTERNET</span>{audit && <button className="secondary" onClick={report} disabled={!!busy}>{busy === "report" ? "Building report…" : "Download proof report"}</button>}</div></header>
        <section className="plain-guide"><strong>How NetAudit works</strong><span><b>1</b> Upload configuration</span><span><b>2</b> See risks with proof</span><span><b>3</b> Review suggested fix</span><span><b>4</b> Export report</span></section>
        {notice && <div className="alert success">{notice}<button onClick={() => setNotice("")}>×</button></div>}{error && <div className="alert error">{error}<button onClick={() => setError("")}>×</button></div>}
        {!audit ? <section className="upload-stage"><div className="stage-copy"><p className="eyebrow">NEW ASSESSMENT</p><h2>Turn raw configuration into defensible evidence.</h2><p>Upload a Cisco or Fortinet text configuration. Secrets are redacted before immutable storage; compliance decisions remain deterministic.</p><div className="pipeline"><span>01<br /><b>Ingest</b></span><i /> <span>02<br /><b>Normalize</b></span><i /> <span>03<br /><b>Evaluate</b></span><i /> <span>04<br /><b>Remediate</b></span></div></div><label className={`dropzone ${dragging ? "dragging" : ""}`} onDragOver={(e) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={(e) => { e.preventDefault(); setDragging(false); handleFile(e.dataTransfer.files[0]); }}><input type="file" accept=".cfg,.conf,.txt" onChange={(e) => handleFile(e.target.files?.[0])} /><span className="upload-icon">↥</span><strong>{busy === "upload" ? "Evaluating configuration…" : "Drop a configuration here"}</strong><p>or click to browse · .cfg, .conf, .txt · max 10 MB</p></label></section> : <>
          <section className="audit-head"><div><div className="status-line"><span className="status">{audit.status}</span><span>{audit.id}</span></div><h2>{audit.original_filename}</h2><div className="device-meta"><span>Vendor <b>{audit.device?.detected_vendor || "Detected"}</b></span><span>OS <b>{audit.device?.detected_os || "Unknown"}</b></span><span>Parse confidence <b>{Math.round((audit.device?.parsing_confidence || 0) * 100)}%</b></span><span>Policy <b>{audit.policy_bundle_version || "cis-generic-level1@1.0.0"}</b></span><span>SHA-256 <b>{audit.file_hash.slice(0, 12)}…</b></span></div></div><button className="primary" onClick={remediationAction} disabled={!!busy}>{busy === "remediation" ? "Preflighting…" : remediations.length ? "Regenerate fixes" : "Generate safe fixes"}</button></section>
          <section className="metrics">{audit.summary.compliance_score !== null ? <div className="score-card"><ScoreRing value={audit.summary.control_pass_rate ?? audit.summary.compliance_score} /><div><p>Prototype checks passed</p><strong>{audit.summary.controls_passed ?? 0} of {audit.summary.controls_evaluated ?? 11} checks passed</strong><span>CIS-inspired demo rules · not a certification claim</span></div></div> : <div className="empty-card"><p>Not yet evaluated.</p><span>Parsing evidence requires human review before a compliance score exists.</span></div>}{severityOrder.map((level) => <div className="metric" key={level}><span className={`dot ${level.toLowerCase()}`} /><p>{level}</p><strong>{audit.summary.by_severity[level] || 0}</strong></div>)}</section>
          <ConfidenceLedger device={audit.device} />
          <TrustPanel runId={audit.id} token={token} />
          <section className="results-layout"><div className="findings"><div className="section-title"><div><p className="eyebrow">POLICY VERDICTS</p><h2>Findings</h2></div><span>{audit.findings.length} failed controls</span></div><div className="finding-list">{audit.findings.map((finding) => { const proposal = remediations.find((item) => item.control_id === finding.control_id); return <button key={finding.control_id} className={selected?.control_id === finding.control_id ? "selected" : ""} onClick={() => setSelected(finding)}><span className={`severity ${finding.severity.toLowerCase()}`}>{finding.severity}</span><div><strong>{finding.title}</strong><p>{finding.control_id} · {finding.evidence}</p></div><span className="finding-state">{proposal?.applied_at ? "APPLIED" : proposal?.approval_status === "APPROVED" ? "✓ APPROVED" : proposal ? (proposal.preflight_status || proposal.preflight?.status) : "REVIEW"}</span><b>›</b></button>; })}</div></div>{selected && <FindingPanel finding={selected} remediation={selectedRemediation} onDecision={decide} onApply={applyFix} onRollback={rollbackFix} busy={busy === "decision"} runId={audit.id} token={token} role={role} />}</section>
        </>}
      </div>}
  </main>;
}
