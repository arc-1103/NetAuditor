"use client";

import { FormEvent, useMemo, useState } from "react";
import { approveRemediation, askLocalQwen, generateRemediations, generateReport, getAudit, login, openProtectedReport, uploadConfig, USE_MOCK } from "../lib/api";
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
    <section className="qwen-box"><div className="remediation-title"><h3>Live local AI</h3><span className={`model-state ${qwenStatus}`}>{qwenStatus === "ready" ? "QWEN LIVE" : "OPTIONAL"}</span></div><p className="muted">Ask locally running Qwen to explain this result in everyday language. It explains; fixed rules still decide.</p><button className="secondary" onClick={explain} disabled={qwenStatus === "asking"}>{qwenStatus === "asking" ? "Qwen is thinking…" : "Ask Qwen to explain"}</button>{qwenAnswer && <p className="ai-answer">{qwenAnswer}</p>}{qwenStatus === "error" && <p className="source">Local model unavailable. Start scripts/start_live_qwen.sh.</p>}</section>
    {!remediation ? <div className="empty-card"><p>No proposal generated yet.</p><span>Generate deterministic fixes for this audit from the toolbar.</span></div> : <section>
      <div className="remediation-title"><h3>Proposed remediation</h3><span className={`preflight ${(status || "unavailable").toLowerCase()}`}>{status || "UNKNOWN"}</span></div>
      {remediation.source === "agentic_rag" && <div className="alert error">AI-synthesized draft · cannot be directly approved</div>}
      {flags.length > 0 && <div className="alert warning">{flags.join(" · ")}</div>}
      <pre className="command">{remediation.script}</pre>
      <div className="decision-row"><button className="secondary" disabled={busy} onClick={() => onDecision(false)}>Reject</button><button className="primary" disabled={busy || status !== "SAFE"} onClick={() => onDecision(true)}>{remediation.approval_status === "APPROVED" ? "Approved ✓" : "Approve safe fix"}</button></div>
    </section>}
  </aside>;
}

export default function Home() {
  const [token, setToken] = useState(""); const [email, setEmail] = useState("");
  const [audit, setAudit] = useState<AuditRun | null>(null); const [selected, setSelected] = useState<Finding | null>(null);
  const [remediations, setRemediations] = useState<Remediation[]>([]); const [busy, setBusy] = useState("");
  const [notice, setNotice] = useState(""); const [error, setError] = useState(""); const [dragging, setDragging] = useState(false);
  const selectedRemediation = useMemo(() => remediations.find((item) => item.control_id === selected?.control_id), [remediations, selected]);

  async function handleFile(file?: File) {
    if (!file) return;
    const extension = file.name.slice(file.name.lastIndexOf(".")).toLowerCase();
    if (![".cfg", ".conf", ".txt"].includes(extension)) { setError("Choose a .cfg, .conf or .txt configuration file."); return; }
    if (file.size > 10 * 1024 * 1024) { setError("Configuration files must be 10 MB or smaller."); return; }
    setBusy("upload"); setError(""); setNotice("Configuration accepted. Parsing and deterministic policy evaluation are running…");
    try { const uploaded = await uploadConfig(file, token); const run = await getAudit(uploaded.job_id, token); setAudit({ ...run, original_filename: USE_MOCK ? file.name : run.original_filename }); setSelected(run.findings[0] || null); setNotice(run.status === "NEEDS_REVIEW" ? "No compliance verdict was issued: parsing evidence requires human review." : "Audit completed. Every verdict below was produced by version-controlled policy."); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Upload failed"); }
    finally { setBusy(""); }
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
  return <main className="app-shell">
    <nav className="sidebar"><div className="brand"><span className="brand-mark">N</span><span>NETAUDIT</span></div><div className="nav-items"><button className="active">⌁<span>Audit workspace</span></button><button>▦<span>Device inventory</span></button><button>◎<span>Learning queue</span></button><button>◫<span>Reports</span></button></div><div className="method-card"><span className="pulse"/><strong>Decision boundary active</strong><p>AI extracts. OPA decides.</p></div><div className="user"><span>{email.slice(0, 1).toUpperCase()}</span><div><strong>{email}</strong><small>Administrator</small></div></div></nav>
    <div className="workspace"><header><div><p className="eyebrow">SECURITY OPERATIONS</p><h1>Audit workspace</h1></div><div className="header-actions"><span className="airgap">● WORKS WITHOUT INTERNET</span>{audit && <button className="secondary" onClick={report} disabled={!!busy}>{busy === "report" ? "Building report…" : "Download proof report"}</button>}</div></header>
      <section className="plain-guide"><strong>How NetAudit works</strong><span><b>1</b> Upload configuration</span><span><b>2</b> See risks with proof</span><span><b>3</b> Review suggested fix</span><span><b>4</b> Export report</span></section>
      {notice && <div className="alert success">{notice}<button onClick={() => setNotice("")}>×</button></div>}{error && <div className="alert error">{error}<button onClick={() => setError("")}>×</button></div>}
      {!audit ? <section className="upload-stage"><div className="stage-copy"><p className="eyebrow">NEW ASSESSMENT</p><h2>Turn raw configuration into defensible evidence.</h2><p>Upload a Cisco or Fortinet text configuration. Secrets are redacted before immutable storage; compliance decisions remain deterministic.</p><div className="pipeline"><span>01<br/><b>Ingest</b></span><i/> <span>02<br/><b>Normalize</b></span><i/> <span>03<br/><b>Evaluate</b></span><i/> <span>04<br/><b>Remediate</b></span></div></div><label className={`dropzone ${dragging ? "dragging" : ""}`} onDragOver={(e) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={(e) => { e.preventDefault(); setDragging(false); handleFile(e.dataTransfer.files[0]); }}><input type="file" accept=".cfg,.conf,.txt" onChange={(e) => handleFile(e.target.files?.[0])}/><span className="upload-icon">↥</span><strong>{busy === "upload" ? "Evaluating configuration…" : "Drop a configuration here"}</strong><p>or click to browse · .cfg, .conf, .txt · max 10 MB</p></label></section> : <>
        <section className="audit-head"><div><div className="status-line"><span className="status">{audit.status}</span><span>{audit.id}</span></div><h2>{audit.original_filename}</h2><div className="device-meta"><span>Vendor <b>{audit.device?.detected_vendor || "Detected"}</b></span><span>OS <b>{audit.device?.detected_os || "Unknown"}</b></span><span>Parse confidence <b>{Math.round((audit.device?.parsing_confidence || 0) * 100)}%</b></span><span>Policy <b>{audit.policy_bundle_version || "cis-generic-level1@1.0.0"}</b></span><span>SHA-256 <b>{audit.file_hash.slice(0, 12)}…</b></span></div></div><button className="primary" onClick={remediationAction} disabled={!!busy}>{busy === "remediation" ? "Preflighting…" : remediations.length ? "Regenerate fixes" : "Generate safe fixes"}</button></section>
        <section className="metrics"><div className="score-card"><ScoreRing value={audit.summary.control_pass_rate ?? audit.summary.compliance_score}/><div><p>Prototype checks passed</p><strong>{audit.summary.controls_passed ?? 0} of {audit.summary.controls_evaluated ?? 11} checks passed</strong><span>CIS-inspired demo rules · not a certification claim</span></div></div>{severityOrder.map((level) => <div className="metric" key={level}><span className={`dot ${level.toLowerCase()}`}/><p>{level}</p><strong>{audit.summary.by_severity[level] || 0}</strong></div>)}</section>
        <section className="results-layout"><div className="findings"><div className="section-title"><div><p className="eyebrow">POLICY VERDICTS</p><h2>Findings</h2></div><span>{audit.findings.length} failed controls</span></div><div className="finding-list">{audit.findings.map((finding) => { const proposal = remediations.find((item) => item.control_id === finding.control_id); return <button key={finding.control_id} className={selected?.control_id === finding.control_id ? "selected" : ""} onClick={() => setSelected(finding)}><span className={`severity ${finding.severity.toLowerCase()}`}>{finding.severity}</span><div><strong>{finding.title}</strong><p>{finding.control_id} · {finding.evidence}</p></div><span className="finding-state">{proposal?.approval_status === "APPROVED" ? "✓ APPROVED" : proposal ? (proposal.preflight_status || proposal.preflight?.status) : "REVIEW"}</span><b>›</b></button>; })}</div></div>{selected && <FindingPanel key={selected.control_id} finding={selected} remediation={selectedRemediation} onDecision={decide} busy={busy === "decision"}/>}</section>
      </>}
    </div>
  </main>;
}
