"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import { approveRemediation, askLocalQwen, generateRemediations, generateReport, getAudit, getLearningQueue, login, openProtectedReport, uploadConfig, USE_MOCK } from "../lib/api";
import type { AuditRun, Finding, Remediation, Severity } from "../lib/types";

const severityOrder: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

function Login({ onLogin }: { onLogin: (token: string, email: string) => void }) {
  const [email, setEmail] = useState("admin@netaudit.local");
  const [password, setPassword] = useState("changeme");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError("");
    try { const result = await login(email, password); onLogin(result.access_token, result.user.email); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Login failed"); }
    finally { setBusy(false); }
  }
  return <main className="login-shell">
    <section className="login-story">
      <div className="brand"><span className="brand-mark">N</span><span>NETAUDIT</span></div>
      <div className="story-copy">
        <p className="eyebrow">SIH 26155 · NTRO</p>
        <h1>See the risk.<br/><em>Prove</em> the fix.</h1>
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

function FindingPanel({ finding, remediation, onDecision, busy }: { finding: Finding; remediation?: Remediation; onDecision: (approved: boolean) => void; busy: boolean }) {
  const status = remediation?.preflight_status || remediation?.preflight?.status;
  const flags = remediation?.risk_flags || remediation?.preflight?.risk_flags || [];
  const [qwenAnswer, setQwenAnswer] = useState("");
  const [qwenStatus, setQwenStatus] = useState("");
  async function explain() {
    setQwenStatus("asking"); setQwenAnswer("");
    try { setQwenAnswer(await askLocalQwen(finding.title, finding.evidence)); setQwenStatus("ready"); }
    catch { setQwenStatus("error"); }
  }
  return <aside className="drawer">
    <div className="drawer-head"><div><span className={`severity ${finding.severity.toLowerCase()}`}>{finding.severity}</span><p>{finding.control_id} · {finding.framework}</p></div></div>
    <h2>{finding.title}</h2>
    <section><h3>What we found</h3><pre className="evidence">{finding.evidence}</pre><EvidenceLines finding={finding}/></section>
    <section><h3>Why this matters</h3><p className="muted">In simple terms, this setting may let an attacker reach or control the device more easily. A person must review every suggested fix before approval.</p>{finding.blast_radius?.length ? <p className="blast">Other devices that may be affected · {finding.blast_radius.join(" · ")}</p> : null}</section>
    <section className="qwen-box"><div className="remediation-title"><h3>Live local AI</h3><span className={`model-state ${qwenStatus}`}>{qwenStatus === "ready" ? "QWEN LIVE" : "OPTIONAL"}</span></div><p className="muted">Ask locally running Qwen to explain this result in everyday language. It explains; fixed rules still decide.</p><button className="secondary" onClick={explain} disabled={qwenStatus === "asking"}>{qwenStatus === "asking" ? "Qwen is thinking…" : "Ask Qwen to explain"}</button>{qwenAnswer && <p className="ai-answer">{qwenAnswer}</p>}{qwenStatus === "error" && <p className="source">Local model unavailable. Run: ollama serve</p>}</section>
    {!remediation ? <div className="empty-card"><p>No proposal generated yet.</p><span>Generate deterministic fixes for this audit from the toolbar.</span></div> : <section>
      <div className="remediation-title"><h3>Proposed remediation</h3><span className={`preflight ${(status || "unavailable").toLowerCase()}`}>{status || "UNKNOWN"}</span></div>
      {remediation.source === "agentic_rag" && <div className="alert error">AI-synthesized draft · cannot be directly approved</div>}
      {flags.length > 0 && <div className="alert warning">{flags.join(" · ")}</div>}
      <pre className="command">{remediation.script}</pre>
      <div className="decision-row"><button className="secondary" disabled={busy} onClick={() => onDecision(false)}>Reject</button><button className="primary" disabled={busy || status !== "SAFE"} onClick={() => onDecision(true)}>{remediation.approval_status === "APPROVED" ? "Approved ✓" : "Approve safe fix"}</button></div>
    </section>}
  </aside>;
}

function LearningQueue({ token }: { token: string }) {
  const [items, setItems] = useState<any[] | null>(null);
  const [loadError, setLoadError] = useState("");
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    setItems(null); setLoadError("");
    getLearningQueue(token).then((res) => setItems(res.items || [])).catch(() => setLoadError("offline"));
  }, [token, attempt]);
  return <div className="workspace"><header><div><p className="eyebrow">SECURITY OPERATIONS</p><h1>Learning queue</h1></div></header>
    {loadError && <div className="empty-card">
      <p>Learning service is offline</p>
      <span>This optional service queues configuration blocks the model couldn&apos;t recognize, so a human can teach it new syntax. It isn&apos;t part of the core audit path — findings and reports work without it.</span>
      <div className="decision-row"><button className="secondary" onClick={() => setAttempt((n) => n + 1)}>Retry</button></div>
    </div>}
    {!loadError && items === null && <p className="muted">Loading queue…</p>}
    {!loadError && items?.length === 0 && <p className="muted">No unrecognized configuration blocks are waiting for review.</p>}
    {!loadError && items && items.length > 0 && <div className="finding-list">{items.map((item, index) => <div key={item.id || index} className="empty-card"><p>{item.reason || "Unrecognized block"}</p><span>{item.text || JSON.stringify(item)}</span></div>)}</div>}
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
      if (kind === "download") await generateReport(audit.id, token);
      if (!USE_MOCK) await openProtectedReport(audit.id, token, kind);
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
  const [token, setToken] = useState(() => readSession("na_token", "")); const [email, setEmail] = useState(() => readSession("na_email", ""));
  const [audit, setAudit] = useState<AuditRun | null>(() => readSession("na_audit", null)); const [selected, setSelected] = useState<Finding | null>(null);
  const [inventory, setInventory] = useState<AuditRun[]>(() => readLocal("na_inventory", []));
  useEffect(() => { writeLocal("na_inventory", inventory); }, [inventory]);
  const [remediations, setRemediations] = useState<Remediation[]>(() => readSession("na_remediations", [])); const [busy, setBusy] = useState("");
  const [notice, setNotice] = useState(""); const [error, setError] = useState(""); const [dragging, setDragging] = useState(false);
  const [view, setView] = useState<"workspace" | "inventory" | "learning" | "reports">("workspace");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => readSession("na_sidebar_collapsed", false));
  useEffect(() => { writeSession("na_sidebar_collapsed", sidebarCollapsed); }, [sidebarCollapsed]);
  useEffect(() => { writeSession("na_token", token); writeSession("na_email", email); }, [token, email]);
  useEffect(() => { writeSession("na_audit", audit); if (audit) setSelected((current) => current || audit.findings[0] || null); }, [audit]);
  useEffect(() => { writeSession("na_remediations", remediations); }, [remediations]);
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
    try { const result = await approveRemediation(selected.control_id, audit.id, approved, token); setRemediations((items) => items.map((item) => item.control_id === selected.control_id ? { ...item, approval_status: result.approval_status } : item)); setNotice(approved ? "Safe remediation approved with operator attribution." : "Proposal rejected and retained in the audit trail."); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Decision failed"); }
    finally { setBusy(""); }
  }
  async function report() {
    if (!audit) return; setBusy("report"); setError("");
    try { await generateReport(audit.id, token); setNotice(USE_MOCK ? "Report generated. Real deployment provides PDF, JSON and CEF downloads." : "Evidence report generated and ready to download."); if (!USE_MOCK) await openProtectedReport(audit.id, token, "preview"); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Report generation failed"); }
    finally { setBusy(""); }
  }

  if (!token) return <Login onLogin={(newToken, userEmail) => { setToken(newToken); setEmail(userEmail); }} />;
  return <main className={`app-shell ${sidebarCollapsed ? "sidebar-collapsed" : ""}`}>
    <nav className="sidebar"><div className="sidebar-head"><div className="brand"><span className="brand-mark">N</span><span>NETAUDIT</span></div><button className="sidebar-toggle" onClick={() => setSidebarCollapsed((c) => !c)} aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"} title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}>{sidebarCollapsed ? "»" : "«"}</button></div><div className="nav-items"><button className={view === "workspace" ? "active" : ""} onClick={() => setView("workspace")}>⌁<span>Audit workspace</span></button><button className={view === "inventory" ? "active" : ""} onClick={() => setView("inventory")}>▦<span>Device inventory</span></button><button className={view === "learning" ? "active" : ""} onClick={() => setView("learning")}>◎<span>Learning queue</span></button><button className={view === "reports" ? "active" : ""} onClick={() => setView("reports")}>◫<span>Reports</span></button></div><div className="method-card"><span className="pulse"/><strong>Decision boundary active</strong><p>AI extracts. OPA decides.</p></div><div className="user"><span>{email.slice(0, 1).toUpperCase()}</span><div><strong>{email}</strong><small>Administrator</small></div></div></nav>
    {view === "inventory" ? <DeviceInventory inventory={inventory} onSelect={openFromInventory} /> : view === "learning" ? <LearningQueue token={token} /> : view === "reports" ? <ReportsView audit={audit} token={token} /> :
    <div className="workspace"><header><div><p className="eyebrow">SECURITY OPERATIONS</p><h1>Audit workspace</h1></div><div className="header-actions"><span className="airgap">● WORKS WITHOUT INTERNET</span>{audit && <button className="secondary" onClick={report} disabled={!!busy}>{busy === "report" ? "Building report…" : "Download proof report"}</button>}</div></header>
      <section className="plain-guide"><strong>How NetAudit works</strong><span><b>1</b> Upload configuration</span><span><b>2</b> See risks with proof</span><span><b>3</b> Review suggested fix</span><span><b>4</b> Export report</span></section>
      {notice && <div className="alert success">{notice}<button onClick={() => setNotice("")}>×</button></div>}{error && <div className="alert error">{error}<button onClick={() => setError("")}>×</button></div>}
      {!audit ? <section className="upload-stage"><div className="stage-copy"><p className="eyebrow">NEW ASSESSMENT</p><h2>Turn raw configuration into defensible evidence.</h2><p>Upload a Cisco or Fortinet text configuration. Secrets are redacted before immutable storage; compliance decisions remain deterministic.</p><div className="pipeline"><span>01<br/><b>Ingest</b></span><i/> <span>02<br/><b>Normalize</b></span><i/> <span>03<br/><b>Evaluate</b></span><i/> <span>04<br/><b>Remediate</b></span></div></div><label className={`dropzone ${dragging ? "dragging" : ""}`} onDragOver={(e) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={(e) => { e.preventDefault(); setDragging(false); handleFile(e.dataTransfer.files[0]); }}><input type="file" accept=".cfg,.conf,.txt" onChange={(e) => handleFile(e.target.files?.[0])}/><span className="upload-icon">↥</span><strong>{busy === "upload" ? "Evaluating configuration…" : "Drop a configuration here"}</strong><p>or click to browse · .cfg, .conf, .txt · max 10 MB</p></label></section> : <>
        <section className="audit-head"><div><div className="status-line"><span className="status">{audit.status}</span><span>{audit.id}</span></div><h2>{audit.original_filename}</h2><div className="device-meta"><span>Vendor <b>{audit.device?.detected_vendor || "Detected"}</b></span><span>OS <b>{audit.device?.detected_os || "Unknown"}</b></span><span>Parse confidence <b>{Math.round((audit.device?.parsing_confidence || 0) * 100)}%</b></span><span>Policy <b>{audit.policy_bundle_version || "cis-generic-level1@1.0.0"}</b></span><span>SHA-256 <b>{audit.file_hash.slice(0, 12)}…</b></span></div></div><div className="decision-row"><button className="secondary" onClick={newAudit} disabled={!!busy}>New audit</button><button className="primary" onClick={remediationAction} disabled={!!busy}>{busy === "remediation" ? "Preflighting…" : remediations.length ? "Regenerate fixes" : "Generate safe fixes"}</button></div></section>
        <ConfidenceLedger device={audit.device} />
        <section className="metrics"><div className="score-card"><ScoreRing value={audit.summary.control_pass_rate ?? audit.summary.compliance_score}/><div><p>Prototype checks passed</p><strong>{audit.summary.controls_passed ?? 0} of {audit.summary.controls_evaluated ?? 11} checks passed</strong><span>CIS-inspired demo rules · not a certification claim</span></div></div>{severityOrder.map((level) => <div className="metric" key={level}><span className={`dot ${level.toLowerCase()}`}/><p>{level}</p><strong>{audit.summary.by_severity[level] || 0}</strong></div>)}</section>
        <section className="results-layout"><div className="findings"><div className="section-title"><div><p className="eyebrow">POLICY VERDICTS</p><h2>Findings</h2></div><span>{audit.findings.length} failed controls</span></div><div className="finding-list">{audit.findings.map((finding) => { const proposal = remediations.find((item) => item.control_id === finding.control_id); return <button key={finding.control_id} className={selected?.control_id === finding.control_id ? "selected" : ""} onClick={() => setSelected(finding)}><span className={`severity ${finding.severity.toLowerCase()}`}>{finding.severity}</span><div><strong>{finding.title}</strong><p>{finding.control_id} · {finding.evidence}</p></div><span className="finding-state">{proposal?.approval_status === "APPROVED" ? "✓ APPROVED" : proposal ? (proposal.preflight_status || proposal.preflight?.status) : "REVIEW"}</span><b>›</b></button>; })}</div></div>{selected && <FindingPanel key={selected.control_id} finding={selected} remediation={selectedRemediation} onDecision={decide} busy={busy === "decision"}/>}</section>
      </>}
    </div>}
  </main>;
}
