"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  applyRemediation, approveRemediation, askLocalQwen, collectConfig, generateRemediations, generateReport, getAudit,
  getAuditTrust, getExecutiveReport, getLearningQueue, getDrift, getHistory, getLedgerProof, grantWaiver, listWaivers, revokeWaiver, getLedgerStatus, sealLedger, verifyLedger, getProvenance, getTimeStatus, getTopology, listAuditRunIds, login, openProtectedReport,
  rollbackRemediation, Role, searchKnowledge, simulateFix, submitLearningMap, uploadConfig, USE_MOCK,
} from "../lib/api";
import RemediationActionCard from "../components/RemediationActionCard";
import { RiskMapView, SimilarityPlot, TrendChart, VerificationPipeline } from "./widgets";
import type { CollectTarget, LedgerStatus, LedgerVerification, TimeStatus } from "../lib/api";
import type { KnowledgeSearchResult, Waiver, AuditRun, ControlResult, ScoreCycle, TwinResult, DeviceHistory, DriftResult, ExecutiveReport, Finding, FixSimulation, LearningQueueItem, ProvenanceChain, Remediation, Severity, TopologyGraph, TrustView } from "../lib/types";

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

function ConfidenceLedger({ device, status }: { device?: AuditRun["device"]; status: string }) {
  const logprob = device?.mean_logprob;
  const fidelity = device?.reverse_translation_fidelity;
  const logprobLabel = logprob == null ? null : logprob >= -0.3 ? "High" : logprob >= -0.5 ? "Borderline" : "Low";
  return <section className="confidence-ledger">
    <VerificationPipeline device={device} status={status} />
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

function ControlResults({ results }: { results?: ControlResult[] }) {
  if (!results || results.length === 0) return null;
  const passed = results.filter((r) => r.result === "PASS").length;
  return <details className="control-results"><summary>All controls · {passed} PASS · {results.length - passed} FAIL</summary>
    {results.map((row) => <p key={row.control_id} className="control-row"><span className={`result-badge ${row.result.toLowerCase()}`}>{row.result}</span><span className={`severity ${row.severity.toLowerCase()}`}>{row.severity}</span><span>{row.control_id} · {row.title}</span></p>)}
  </details>;
}

function TimeBadge({ token }: { token: string }) {
  const [status, setStatus] = useState<TimeStatus | null>(null);
  useEffect(() => { getTimeStatus(token).then(setStatus).catch(() => setStatus({ state: "UNAVAILABLE" })); }, [token]);
  if (!status) return null;
  const label = status.state === "OK" ? `TIME SYNCED · ${Math.round((status.offset_seconds ?? 0) * 1000)} ms`
    : status.state === "DRIFT" ? "CLOCK DRIFT" : status.state === "UNAVAILABLE" ? "TIME SOURCE DOWN" : "TIME NOT VERIFIED";
  const title = status.server ? `Checked against ${status.server}${status.stratum ? `, stratum ${status.stratum}` : ""}` : "No internal NTP source is configured (NTP_SERVER)";
  return <span className={`airgap time-badge ${status.state.toLowerCase()}`} title={title}>● {label}</span>;
}

function CollectForm({ onCollect, busy }: { onCollect: (target: CollectTarget) => void; busy: boolean }) {
  const [open, setOpen] = useState(false);
  const [target, setTarget] = useState<CollectTarget>({ host: "", device_type: "cisco_ios", username: "", password: "", port: 22, method: "netmiko" });
  const set = <K extends keyof CollectTarget>(key: K, value: CollectTarget[K]) => setTarget((t) => ({ ...t, [key]: value }));
  const ready = target.host.trim() && target.username.trim() && target.password;
  return <div className="collect-box">
    <button type="button" className="secondary" onClick={() => setOpen((v) => !v)}>{open ? "Hide online collection" : "Or collect from a device (online mode)"}</button>
    {open && <div className="teach-form">
      <p className="source">Uses Netmiko or NAPALM over SSH. Disabled in air-gapped deployments, where you upload the file instead. The password is used once and never stored.</p>
      <label>Device address<input value={target.host} onChange={(e) => set("host", e.target.value)} placeholder="10.20.0.5 or core-sw1" autoComplete="off" /></label>
      <label>Device type<select value={target.device_type} onChange={(e) => set("device_type", e.target.value)}>{["cisco_ios", "cisco_xe", "cisco_nxos", "cisco_asa", "arista_eos", "juniper_junos", "fortinet", "paloalto_panos"].map((t) => <option key={t} value={t}>{t}</option>)}</select></label>
      <label>Library<select value={target.method} onChange={(e) => set("method", e.target.value as "netmiko" | "napalm")}><option value="netmiko">Netmiko</option><option value="napalm">NAPALM</option></select></label>
      <label>Username<input value={target.username} onChange={(e) => set("username", e.target.value)} autoComplete="off" /></label>
      <label>Password<input type="password" value={target.password} onChange={(e) => set("password", e.target.value)} autoComplete="new-password" /></label>
      <div className="decision-row"><button type="button" className="primary" disabled={busy || !ready} onClick={() => { onCollect(target); set("password", ""); }}>{busy ? "Collecting…" : "Collect and audit"}</button></div>
    </div>}
  </div>;
}

function DriftDetail({ runId, controlId, token }: { runId: string; controlId: string; token: string }) {
  const [drift, setDrift] = useState<DriftResult | null>(null);
  const [state, setState] = useState<"idle" | "loading" | "error">("idle");
  const [message, setMessage] = useState("");
  useEffect(() => { setDrift(null); setState("idle"); setMessage(""); }, [runId, controlId]);
  async function load() {
    setState("loading");
    try { setDrift(await getDrift(runId, controlId, token)); setState("idle"); }
    catch (reason) { setState("error"); setMessage(reason instanceof Error ? reason.message : "Could not compare"); }
  }
  const show = (value: unknown) => value === null || value === undefined ? "(not set)" : typeof value === "string" ? value : JSON.stringify(value);
  return <div className="drift-detail">
    <button className="secondary" onClick={load} disabled={state === "loading"}>{state === "loading" ? "Comparing…" : "What changed since it last passed?"}</button>
    {state === "error" && <p className="source">{message}</p>}
    {drift && (drift.compared_to === null ? <p className="source">{drift.note}</p> : <>
      <p className="source">Compared with the audit of {new Date(drift.compared_to.created_at).toLocaleString()}{drift.compared_to.filename ? ` (${drift.compared_to.filename})` : ""}, when this control passed.</p>
      {drift.changes.length === 0 ? <p className="source">No configuration fields differ from that audit.</p> : drift.changes.map((change) => <p key={change.path} className={`drift-change ${change.related ? "related" : ""}`}><code>{change.path}</code> {show(change.before)} → <b>{show(change.after)}</b>{change.related ? " · caused this failure" : ""}</p>)}
      {drift.evidence && <pre className="evidence">{drift.evidence.text}</pre>}
    </>)}
  </div>;
}

function HistoryPanel({ runId, controlId, token }: { runId: string; controlId: string; token: string }) {
  const [history, setHistory] = useState<DeviceHistory | null>(null);
  useEffect(() => {
    setHistory(null);
    getHistory(runId, token).then(setHistory).catch(() => setHistory(null));
  }, [runId, token]);
  if (!history || history.runs.length === 0) return null;
  const streak = history.control_streaks[controlId];
  const when = (iso: string) => new Date(iso).toLocaleDateString();
  const last = history.transitions[history.transitions.length - 1];
  return <section><h3>Drift history</h3>
    <p className="muted">{history.runs.length} audit{history.runs.length === 1 ? "" : "s"} of this device on record.</p>
    {streak && <p className="source">{streak.first_audit_of_device ? "Failing since the first audit of this device" : `Started failing in the audit of ${when(streak.failing_since)}`} · {streak.audits_failing} audit{streak.audits_failing === 1 ? "" : "s"} in a row{streak.last_passed_run ? " · passed before that" : ""}.</p>}
    {last && <p className="source">Latest change ({when(last.created_at)}): {last.introduced.length} new, {last.resolved.length} resolved, score {last.score_change >= 0 ? "+" : ""}{Math.round(last.score_change)}.</p>}
    {streak && <DriftDetail runId={runId} controlId={controlId} token={token} />}
  </section>;
}

function WaiverPanel({ finding, runId, token, role, onChanged }: { finding: Finding; runId: string; token: string; role: Role; onChanged: () => void }) {
  const inThirtyDays = new Date(Date.now() + 30 * 864e5).toISOString().slice(0, 10);
  const maxDay = new Date(Date.now() + 90 * 864e5).toISOString().slice(0, 10);
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [until, setUntil] = useState(inThirtyDays);
  const [ticket, setTicket] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => { setOpen(false); setReason(""); setError(""); }, [finding.control_id, runId]);
  async function act(run: () => Promise<unknown>) {
    setBusy(true); setError("");
    try { await run(); setOpen(false); setReason(""); onChanged(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Request failed"); }
    finally { setBusy(false); }
  }
  const waiver = finding.waiver;
  return <section className="waiver-panel"><h3>Accepted risk (waiver)</h3>
    {waiver ? <>
      <p className="waiver-active"><span className="result-badge waived">WAIVED</span> until <b>{new Date(waiver.expires_at).toLocaleDateString()}</b> · granted by {waiver.granted_by}{waiver.ticket ? ` · ${waiver.ticket}` : ""}</p>
      <p className="muted">{waiver.reason}</p>
      <p className="source">The finding is still recorded as a failure in the evidence; it is excluded from the score and from new alerts until the waiver ends. The grant is in the tamper-evident ledger.</p>
      {role === "admin" && <div className="decision-row"><button className="secondary" disabled={busy} onClick={() => act(() => revokeWaiver(waiver.waiver_id, "Revoked from the audit workspace", token))}>Revoke waiver</button></div>}
    </> : <>
      {finding.waiver_note && <p className="source">{finding.waiver_note}</p>}
      {role !== "admin" ? <p className="source">Only an administrator can accept the risk of a failing control.</p> : !open
        ? <div className="decision-row"><span className="source">For a deliberate exception, such as an isolated legacy system or a honeypot.</span><button className="secondary" onClick={() => setOpen(true)}>Waive this finding…</button></div>
        : <div className="teach-form">
          <label>Justification (required, kept in the ledger)<textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={3} placeholder="e.g. Isolated legacy system for mission 4417; compensating control: air-gapped VLAN" /></label>
          <label>Waiver ends on (automatic, max 90 days)<input type="date" value={until} min={new Date().toISOString().slice(0, 10)} max={maxDay} onChange={(e) => setUntil(e.target.value)} /></label>
          <label>Change / ticket reference (optional)<input value={ticket} onChange={(e) => setTicket(e.target.value)} placeholder="CHG-1234" /></label>
          <div className="decision-row"><button className="secondary" disabled={busy} onClick={() => setOpen(false)}>Cancel</button>
            <button className="primary" disabled={busy || reason.trim().length < 15} onClick={() => act(() => grantWaiver({ audit_run_id: runId, control_id: finding.control_id, reason, expires_at: `${until}T23:59:59Z`, ticket: ticket || undefined }, token))}>{busy ? "Recording…" : "Grant waiver"}</button></div>
        </div>}
    </>}
    {error && <p className="source">{error}</p>}
  </section>;
}

function WaiverRegister({ token, role }: { token: string; role: Role }) {
  const [waivers, setWaivers] = useState<Waiver[] | null>(null);
  const [error, setError] = useState("");
  const load = () => listWaivers(token).then(setWaivers).catch((cause) => setError(cause instanceof Error ? cause.message : "Could not load waivers"));
  useEffect(() => { load(); }, [token]);
  if (error && !waivers) return <div className="empty-card waiver-register"><p>Waivers</p><div className="alert error">{error}</div></div>;
  if (!waivers || waivers.length === 0) return <div className="empty-card waiver-register"><p>Waivers</p><span>No risk has been accepted. A waiver is a dated, reasoned exception recorded in the ledger.</span></div>;
  return <div className="empty-card waiver-register"><p>Waivers · accepted risk</p>
    <table className="mini-table"><thead><tr><th>Control</th><th>Device</th><th>Status</th><th>Ends</th><th>By</th><th /></tr></thead><tbody>
      {waivers.map((w) => <tr key={w.waiver_id} title={w.reason}><td>{w.control_id}</td><td>{w.device_key}</td><td><span className={`result-badge ${w.status === "ACTIVE" ? "waived" : "fail"}`}>{w.status}</span></td><td>{new Date(w.expires_at).toLocaleDateString()}</td><td>{w.granted_by}</td>
        <td>{role === "admin" && w.status === "ACTIVE" && <button className="secondary" onClick={() => { setError(""); revokeWaiver(w.waiver_id, "Revoked from the register", token).then(load).catch((cause) => setError(cause instanceof Error ? cause.message : "Could not revoke the waiver")); }}>Revoke</button>}</td></tr>)}
    </tbody></table>{error && <div className="alert error">{error}</div>}</div>;
}

function CadenceNote({ label, cycle }: { label: string; cycle?: ScoreCycle }) {
  if (!cycle) return null;
  const days = cycle.detected ? Array.from(new Set(cycle.markers.map((m) => new Date(`${m.date}T12:00:00`).toLocaleDateString(undefined, { weekday: "long" })))) : [];
  return <p className={`source cadence ${cycle.detected ? "hit" : ""}`}><b>{label}:</b> {cycle.detected
    ? `${cycle.note} Peaks fall on ${days.join(", ")}. Autocorrelation ${cycle.autocorrelation_at_period}, permutation p = ${cycle.p_value}.`
    : cycle.note}</p>;
}

function TwinSummary({ remediations }: { remediations: Remediation[] }) {
  if (remediations.length === 0) return <p className="source twin-summary">Each fix is simulated on this device before it can be approved.</p>;
  const modeled = remediations.filter((r) => r.twin?.modeled && r.twin.checks.length > 0);
  const checks = modeled.reduce((n, r) => n + (r.twin?.checks.length ?? 0), 0);
  const broken = modeled.reduce((n, r) => n + (r.twin?.broken ?? 0), 0);
  return <p className={`source twin-summary ${broken ? "bad" : ""}`}>{modeled.length === 0
    ? `Reachability simulation: no ACL changes among these ${remediations.length} fixes needed simulating.`
    : broken ? `Reachability simulation: ${broken} of ${checks} critical paths would break — those fixes cannot be approved.`
    : `Reachability simulation: all ${checks} critical paths preserved across ${modeled.length} fix${modeled.length === 1 ? "" : "es"}.`}</p>;
}

function TwinPanel({ twin }: { twin?: TwinResult | null }) {
  if (!twin) return null;
  return <div className="twin-panel"><p className="source"><b>Digital twin · reachability check</b></p>
    {twin.modeled && twin.checks.length > 0 ? twin.checks.map((check) => <div key={check.description}>
        <p className="twin-row"><span className={`result-badge ${check.result === "BROKEN" ? "fail" : "pass"}`}>{check.result}</span><span>{check.description}{check.method === "z3-smt" ? <em className="proof-tag" title="Checked by the Z3 SMT solver over every packet in the class, not a sample"> Z3 {check.result === "BROKEN" ? "counterexample" : "proof"}</em> : <em className="proof-tag weak" title="Z3 is not installed; one representative packet was evaluated"> sample check</em>}</span></p>
        {check.counterexample && <p className="source counterexample">Blocked packet found: {check.counterexample.proto} {check.counterexample.src}:{check.counterexample.sport} → {check.counterexample.dst}:{check.counterexample.dport}</p>}
      </div>)
      : <p className="source">{twin.note || "No reachability effect was simulated for this change."}</p>}
    {twin.repairs?.map((repair) => <div key={repair.acl} className="twin-repair">
      {repair.status === "REPAIRED" ? <><p className="source"><b>Synthesised repair for ACL {repair.acl}</b> (found in {repair.rounds} counterexample round{repair.rounds === 1 ? "" : "s"}; the repaired ACL is re-proven, and never admits traffic that must stay blocked). Add before the final deny:</p><pre className="command">{repair.add_lines.join("\n")}</pre></>
        : repair.status === "UNREPAIRABLE" ? <p className="source">No safe repair found for ACL {repair.acl}: {repair.reason}</p> : null}
    </div>)}
    {twin.modeled && twin.checks.length > 0 && twin.broken === 0 && <p className="source">Simulated on this device&apos;s stored configuration: no routing session or protected management path is lost.</p>}
  </div>;
}

function SimulationPanel({ runId, controlId, token }: { runId: string; controlId: string; token: string }) {
  const [result, setResult] = useState<FixSimulation | null>(null);
  const [state, setState] = useState<"idle" | "running" | "error">("idle");
  const [message, setMessage] = useState("");
  useEffect(() => { setResult(null); setState("idle"); setMessage(""); }, [runId, controlId]);
  async function run() {
    setState("running"); setMessage("");
    try { setResult(await simulateFix(runId, controlId, token)); setState("idle"); }
    catch (reason) { setState("error"); setMessage(reason instanceof Error ? reason.message : "Simulation failed"); }
  }
  const delta = result ? Math.round(result.compliance_delta) : 0;
  return <section><div className="remediation-title"><h3>Simulate this fix</h3><span className="model-state">WHAT-IF</span></div>
    <p className="muted">Re-scores this device as if the control were fixed, using the same policy engine. It assumes the fix achieves the intended setting.</p>
    <button className="secondary" onClick={run} disabled={state === "running"}>{state === "running" ? "Simulating…" : result ? "Run again" : "Simulate fix"}</button>
    {state === "error" && <p className="source">{message}</p>}
    {result && <div className="sim-result">
      <div className="sim-score"><span>{Math.round(result.current.compliance_score)}</span><b>→</b><span>{Math.round(result.proposed.compliance_score)}</span><em className={delta >= 0 ? "up" : "down"}>{delta >= 0 ? "+" : ""}{delta}</em></div>
      <p className="source">Resolves {result.violations_resolved.length ? result.violations_resolved.join(", ") : "nothing"} · introduces {result.violations_introduced.length ? result.violations_introduced.join(", ") : "nothing new"}</p>
      <span className={`preflight ${result.verdict === "SAFE" ? "safe" : "risk_flags"}`}>{result.verdict === "SAFE" ? "NO REGRESSION" : "RISK FLAG"} · {result.risk} RISK</span>
    </div>}
  </section>;
}

function TopologyPanel({ runId, token, affected }: { runId: string; token: string; affected?: string[] }) {
  const [graph, setGraph] = useState<TopologyGraph | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    setGraph(null); setFailed(false);
    getTopology(runId, token).then(setGraph).catch(() => setFailed(true));
  }, [runId, token]);
  const W = 360, H = 250, cx = W / 2, cy = H / 2 - 6, radius = 88;
  const nodes = graph?.nodes ?? [];
  const others = nodes.filter((n) => n.id !== graph?.center);
  const pos = new Map<string, { x: number; y: number }>();
  if (graph?.center) pos.set(graph.center, { x: cx, y: cy });
  others.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / others.length - Math.PI / 2;
    pos.set(n.id, { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) });
  });
  const label = (n: TopologyGraph["nodes"][number]) => n.kind === "unresolved" ? (n.ip || "unscanned") : (n.hostname || n.id.slice(0, 8));
  return <section className="topology"><h3>Network neighborhood</h3>
    {failed ? <p className="source">Topology service unavailable.</p>
      : !graph ? <p className="source">Loading topology…</p>
      : others.length === 0 ? <p className="source">No routing neighbors known for this device. Topology needs Neo4j (docker compose --profile advanced) and other audited devices that peer with it.</p>
      : <>
        <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Routing neighborhood: ${others.length} connected device${others.length === 1 ? "" : "s"}`}>
          {graph.edges.map((e, i) => { const a = pos.get(e.source), b = pos.get(e.target); return a && b ? <line key={i} className="topo-edge" x1={a.x} y1={a.y} x2={b.x} y2={b.y}><title>{e.protocol || "routes to"}</title></line> : null; })}
          {nodes.map((n) => { const p = pos.get(n.id); if (!p) return null; const isCenter = n.id === graph.center;
            return <g key={n.id} className={`topo-node ${isCenter ? "center" : n.kind}`} transform={`translate(${p.x},${p.y})`}>
              <circle r={isCenter ? 14 : 10} /><title>{n.kind === "unresolved" ? `Not yet scanned · ${n.ip}` : `${n.hostname || n.id}${n.vendor ? ` · ${n.vendor}` : ""}`}</title>
              <text y={isCenter ? 28 : 24} textAnchor="middle">{label(n)}</text>
            </g>; })}
        </svg>
        <p className="source">{others.length} device{others.length === 1 ? "" : "s"} reachable via routing adjacency{affected?.length ? ` · ${affected.length} in this finding's blast radius` : ""}. Dashed nodes are peers that haven&apos;t been audited yet.</p>
      </>}
  </section>;
}

function ScoreRing({ value }: { value: number }) {
  const color = value >= 80 ? "var(--score-good)" : value >= 50 ? "var(--score-mid)" : "var(--score-bad)";
  return <div className="score-ring" style={{ background: `conic-gradient(${color} ${value * 3.6}deg, var(--ring-track) 0deg)` }}>
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
  const [proofMessage, setProofMessage] = useState("");
  async function downloadProof(eventId: string) {
    setProofMessage("");
    try {
      const proof = await getLedgerProof(eventId, token);
      const url = URL.createObjectURL(new Blob([JSON.stringify(proof, null, 2)], { type: "application/json" }));
      const link = document.createElement("a");
      link.href = url; link.download = `ledger-proof-${eventId}.json`; link.click();
      URL.revokeObjectURL(url);
    } catch (reason) { setProofMessage(reason instanceof Error ? `${reason.message} (an event is provable only after the ledger has sealed it)` : "Proof unavailable"); }
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
      <span>{event.actor} · {new Date(event.created_at).toLocaleString()}{event.ruleset_version ? ` · ruleset ${event.ruleset_version}` : ""}{event.id && <> · <button className="link-button" onClick={() => downloadProof(event.id as string)}>inclusion proof</button></>}</span>
    </div>)}
    {proofMessage && <p className="source">{proofMessage}</p>}
    <p className="source">An inclusion proof is checked offline with <code>tools/verify_ledger_proof.py</code>; it proves this event is in a signed, chained seal.</p>
    {chain.policy && <p className="source">Evaluated against policy bundle <b>{String(chain.policy.policy_bundle_version)}</b>, baseline SHA-256 {String(chain.policy.baseline_sha256).slice(0, 16)}…</p>}
  </section>;
}

function FindingPanel({ finding, remediation, device, onDecision, onApply, onRollback, onClose, onWaiverChange, busy, runId, token, role }: {
  finding: Finding; remediation?: Remediation;
  device: { hostname: string; vendor: string; os?: string | null };
  onDecision: (approved: boolean) => void;
  onApply: () => void;
  onRollback: (reason: string) => void;
  onClose: () => void;
  onWaiverChange: () => void;
  busy: boolean; runId: string; token: string; role: Role;
}) {
  const [minimized, setMinimized] = useState(false);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  const [qwenAnswer, setQwenAnswer] = useState("");
  const [qwenStatus, setQwenStatus] = useState("");
  async function explain() {
    setQwenStatus("asking"); setQwenAnswer("");
    try { setQwenAnswer(await askLocalQwen(finding.title, finding.evidence)); setQwenStatus("ready"); }
    catch { setQwenStatus("error"); }
  }
  return <>
  {!minimized && <div className="drawer-backdrop" onClick={onClose} />}
  <aside className={`drawer ${minimized ? "minimized" : ""}`}>
    <div className="drawer-head">
      <div><span className={`severity ${finding.severity.toLowerCase()}`}>{finding.severity}</span><p>{finding.control_id} · {finding.framework}</p></div>
      <div className="drawer-controls">
        <button onClick={() => setMinimized((m) => !m)} aria-label={minimized ? "Expand panel" : "Minimize panel"} title={minimized ? "Expand" : "Minimize"}>{minimized ? "▸" : "–"}</button>
        <button onClick={onClose} aria-label="Close panel" title="Close">×</button>
      </div>
    </div>
    <h2>{finding.title}</h2>
    {!minimized && <>
    <section><h3>What we found</h3><pre className="evidence">{finding.evidence}</pre><EvidenceLines finding={finding} /></section>
    <section><h3>Why this matters</h3><p className="muted">In simple terms, this setting may let an attacker reach or control the device more easily. A person must review every suggested fix before approval.</p>{finding.blast_radius?.length ? <p className="blast">Other devices that may be affected · {finding.blast_radius.join(" · ")}</p> : null}</section>
    <section className="qwen-box"><div className="remediation-title"><h3>Live local AI</h3><span className={`model-state ${qwenStatus}`}>{qwenStatus === "ready" ? "QWEN LIVE" : "OPTIONAL"}</span></div><p className="muted">Ask locally running Qwen to explain this result in everyday language. It explains; fixed rules still decide.</p><button className="secondary" onClick={explain} disabled={qwenStatus === "asking"}>{qwenStatus === "asking" ? "Qwen is thinking…" : "Ask Qwen to explain"}</button>{qwenAnswer && <p className="ai-answer">{qwenAnswer}</p>}{qwenStatus === "error" && <p className="source">Local model unavailable. Run: ollama serve</p>}</section>
    {!remediation ? <div className="empty-card"><p>No proposal generated yet.</p><span>Generate deterministic fixes for this audit from the toolbar.</span></div> : <section>
      <RemediationActionCard finding={finding} remediation={remediation} device={device} role={role} busy={busy}
        onApprove={() => onDecision(true)} onReject={() => onDecision(false)} onMarkApplied={onApply} onRollback={onRollback} />
      <TwinPanel twin={remediation.twin} />
    </section>}
    <WaiverPanel finding={finding} runId={runId} token={token} role={role} onChanged={onWaiverChange} />
    <HistoryPanel runId={runId} controlId={finding.control_id} token={token} />
    <SimulationPanel runId={runId} controlId={finding.control_id} token={token} />
    <TopologyPanel runId={runId} token={token} affected={finding.blast_radius} />
    <ProvenancePanel runId={runId} controlId={finding.control_id} token={token} />
    </>}
  </aside>
  </>;
}

function TeachForm({ item, token, onTaught }: { item: LearningQueueItem; token: string; onTaught: (blockId: string) => void }) {
  const [open, setOpen] = useState(false);
  const [cliPattern, setCliPattern] = useState("");
  const [field, setField] = useState("");
  const [value, setValue] = useState("");
  const [vendor, setVendor] = useState("");
  const [os, setOs] = useState("");
  const [tier, setTier] = useState<"public" | "admin">("admin");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit() {
    setBusy(true); setError("");
    try {
      await submitLearningMap({ block_id: item.block_id, cli_pattern: cliPattern, field, value, vendor: vendor || undefined, os: os || null, access_tier: tier }, token);
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
    <label>Who can retrieve this mapping<select value={tier} onChange={(e) => setTier(e.target.value as "public" | "admin")}><option value="admin">Admin tier — administrators and the internal pipeline only (default)</option><option value="public">Public tier — every signed-in role</option></select></label>
    <p className="source">Text that looks like a prompt-injection attempt is rejected, because saved mappings are fed to the model as trusted grounding.</p>
    {error && <div className="alert error">{error}</div>}
    <div className="decision-row"><button className="secondary" onClick={() => setOpen(false)} disabled={busy}>Cancel</button><button className="primary" disabled={busy || !cliPattern.trim() || !field.trim() || !value.trim()} onClick={submit}>{busy ? "Saving…" : "Confirm mapping"}</button></div>
  </div>;
}

function KnowledgeSearch({ token }: { token: string }) {
  const [query, setQuery] = useState("");
  const [vendor, setVendor] = useState("");
  const [result, setResult] = useState<KnowledgeSearchResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function run() {
    setBusy(true); setError("");
    try { setResult(await searchKnowledge({ query, vendor: vendor || undefined }, token)); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Search failed"); }
    finally { setBusy(false); }
  }
  return <div className="empty-card knowledge-search" style={{ textAlign: "left", marginBottom: 16 }}>
    <p>Search confirmed knowledge</p>
    <span>Hybrid retrieval: vector similarity plus keyword (BM25) matching, fused by rank. Results are filtered to what your role may read before anything is ranked.</span>
    <div className="teach-form">
      <label>Query<input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="e.g. ip access-group MGMT-ONLY in" /></label>
      <label>Vendor (optional, narrows the search)<input value={vendor} onChange={(e) => setVendor(e.target.value)} placeholder="e.g. cisco" /></label>
      <div className="decision-row"><span /><button className="primary" disabled={busy || !query.trim()} onClick={run}>{busy ? "Searching…" : "Search"}</button></div>
    </div>
    {error && <div className="alert error">{error}</div>}
    {result && <>
      <p className="source">You can read the {result.guardrail.visible_tiers.join(" + ") || "—"} tier{result.guardrail.visible_tiers.length > 1 ? "s" : ""}.{result.cache === "semantic_hit" ? " Served from the semantic cache." : ""}{result.rerank && !result.rerank.startsWith("skipped") ? ` Re-ranked by ${result.rerank}.` : ""}</p>
      {result.guardrail.query_flags.length > 0 && <div className="alert error">Guardrail removed text from your query: {result.guardrail.query_flags.join("; ")}</div>}
      {result.guardrail.quarantined > 0 && <div className="alert error">{result.guardrail.quarantined} stored document(s) were withheld because they contained prompt-injection text.</div>}
      {result.matches.length === 0 ? <p className="muted">No matching knowledge you are allowed to read.</p> : <table className="mini-table"><thead><tr><th>Match</th><th>Tier</th><th>Vendor</th><th>Distance</th></tr></thead><tbody>
        {result.matches.map((m) => <tr key={m.id} title={m.document}><td>{String(m.metadata.cli_pattern ?? m.document).slice(0, 80)}</td><td><span className={`result-badge ${m.metadata.access_tier === "admin" ? "fail" : "waived"}`}>{String(m.metadata.access_tier ?? "admin")}</span></td><td>{String(m.metadata.vendor ?? "—")}</td><td>{m.distance?.toFixed(3) ?? "—"}</td></tr>)}
      </tbody></table>}
    </>}
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
    <KnowledgeSearch token={token} />
    {!loadError && items === null && <p className="muted">Loading queue…</p>}
    {!loadError && items?.length === 0 && <p className="muted">No unrecognized configuration blocks are waiting for review.</p>}
    {!loadError && items && items.length > 0 && <div className="finding-list">{items.map((item) => <div key={item.block_id} className="empty-card" style={{ textAlign: "left" }}>
      <p>Unrecognized configuration block</p>
      {item.keywords && item.keywords.length > 0 && <div className="keyword-chips"><span className="source">Unfamiliar keywords found:</span>{item.keywords.map((k) => <span key={k.keyword} className={`keyword-chip ${k.security_related ? "security" : ""}`} title={`${k.count}× · e.g. ${k.example}`}>{k.keyword}{k.security_related ? " · security-related" : ""}</span>)}</div>}
      {item.sections && item.sections.length > 0 && <span className="source" style={{ display: "block", marginBottom: 6 }}>Kept together with its parent block: {item.sections.join(" · ")}</span>}
      <span style={{ display: "block", marginBottom: 8 }}>{item.raw_text}</span>
      <SimilarityPlot blockId={item.block_id} token={token} />
      <TeachForm item={item} token={token} onTaught={onTaught} />
    </div>)}</div>}
  </div>;
}

function DriftCompare({ inventory }: { inventory: AuditRun[] }) {
  const [beforeId, setBeforeId] = useState("");
  const [afterId, setAfterId] = useState("");
  const before = inventory.find((r) => r.id === beforeId);
  const after = inventory.find((r) => r.id === afterId);
  const label = (r: AuditRun) => `${r.original_filename} · ${new Date(r.created_at).toLocaleString()}`;
  const beforeIds = new Set(before?.findings.map((f) => f.control_id));
  const afterIds = new Set(after?.findings.map((f) => f.control_id));
  const groups = before && after ? [
    { title: "Resolved", tone: "safe", items: before.findings.filter((f) => !afterIds.has(f.control_id)) },
    { title: "New", tone: "unavailable", items: after.findings.filter((f) => !beforeIds.has(f.control_id)) },
    { title: "Still failing", tone: "risk_flags", items: after.findings.filter((f) => beforeIds.has(f.control_id)) },
  ] : [];
  const scoreBefore = before?.summary.compliance_score, scoreAfter = after?.summary.compliance_score;
  return <section className="drift"><div className="section-title"><div><p className="eyebrow">CHANGE OVER TIME</p><h2>Compare two audits</h2></div></div>
    <div className="drift-pickers">
      <label>Earlier audit<select value={beforeId} onChange={(e) => setBeforeId(e.target.value)}><option value="">Choose…</option>{inventory.map((r) => <option key={r.id} value={r.id}>{label(r)}</option>)}</select></label>
      <label>Later audit<select value={afterId} onChange={(e) => setAfterId(e.target.value)}><option value="">Choose…</option>{inventory.map((r) => <option key={r.id} value={r.id}>{label(r)}</option>)}</select></label>
    </div>
    {inventory.length < 2 && <p className="source">Audit at least two configurations to compare them.</p>}
    {before && after && <>
      {scoreBefore != null && scoreAfter != null && <p className="drift-score">Score {Math.round(scoreBefore)} → {Math.round(scoreAfter)} <em className={scoreAfter >= scoreBefore ? "up" : "down"}>{scoreAfter >= scoreBefore ? "+" : ""}{Math.round(scoreAfter - scoreBefore)}</em></p>}
      {groups.map((g) => <div key={g.title} className="drift-group"><div className="remediation-title"><h3>{g.title}</h3><span className={`preflight ${g.tone}`}>{g.items.length}</span></div>
        {g.items.length === 0 ? <p className="source">None</p> : g.items.map((f) => <p key={f.control_id} className="drift-row"><span className={`severity ${f.severity.toLowerCase()}`}>{f.severity}</span> {f.control_id} · {f.title}</p>)}
      </div>)}
    </>}
  </section>;
}

function DeviceInventory({ inventory, onSelect }: { inventory: AuditRun[]; onSelect: (run: AuditRun) => void }) {
  return <div className="workspace"><header><div><p className="eyebrow">SECURITY OPERATIONS</p><h1>Device inventory</h1></div></header>
    {inventory.length > 0 && <DriftCompare inventory={inventory} />}
    {inventory.length === 0 ? <p className="muted">No device has been audited yet this session. Upload a configuration from Audit workspace first.</p> : <div className="finding-list">{inventory.map((run) => <button key={run.id} onClick={() => onSelect(run)} style={{ gridTemplateColumns: "1fr auto" }}>
      <div><strong>{run.original_filename}</strong><p>Vendor {run.device?.detected_vendor || "Detected"} · OS {run.device?.detected_os || "Unknown"} · Parse confidence {Math.round((run.device?.parsing_confidence || 0) * 100)}% · SHA-256 {run.file_hash.slice(0, 16)}…</p></div>
      <span className="finding-state">{run.summary?.total_findings ?? 0} findings</span>
    </button>)}</div>}
  </div>;
}

function AnomalyChip({ anomaly }: { anomaly?: AuditRun["anomaly"] }) {
  if (!anomaly) return null;
  const label = anomaly.status === "scored" ? (anomaly.is_anomaly ? "Unusual versus peers" : "Typical for peers")
    : anomaly.status === "insufficient_peers" ? "Not enough peer devices to compare" : "Not compared";
  return <span title="Unsupervised comparison of this device's settings with other devices of the same vendor and OS. A signal shown beside findings; it never changes a verdict.">Peer comparison <b className={anomaly.is_anomaly ? "anomaly-hot" : ""}>{label}</b></span>;
}

function FleetPosture({ token, role, onOpen, refreshKey }: { token: string; role: Role; onOpen: (view: "inventory" | "learning" | "reports" | "executive" | "workspace") => void; refreshKey: string }) {
  const [open, setOpen] = useState(() => readLocal("netaudit.fleetPosture.open", true));
  const [report, setReport] = useState<ExecutiveReport | null>(null);
  const [ledger, setLedger] = useState<LedgerStatus | null>(null);
  const [verified, setVerified] = useState<boolean | null>(null);
  const [waivers, setWaivers] = useState<Waiver[] | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    getExecutiveReport(token).then(setReport).catch((reason) => setError(reason instanceof Error ? reason.message : "Fleet data unavailable"));
    getLedgerStatus(token).then(setLedger).catch(() => setLedger(null));
    verifyLedger(token).then((v) => setVerified(v.ok)).catch(() => setVerified(null));
    listWaivers(token).then(setWaivers).catch(() => setWaivers(null));
  }, [token, refreshKey]);
  useEffect(() => { writeLocal("netaudit.fleetPosture.open", open); }, [open]);
  const active = (waivers ?? []).filter((w) => w.status === "ACTIVE").length;
  return <section className="fleet-posture">
    <button className="fleet-toggle" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
      <span className="eyebrow">FLEET POSTURE</span>
      <span className="fleet-summary">
        {report ? `${report.fleet_score.fleet_score}/100 across ${report.fleet_score.devices_scored} device${report.fleet_score.devices_scored === 1 ? "" : "s"}` : error ? "unavailable" : "loading…"}
        {ledger && ` · ledger ${verified === true ? "verified" : verified === false ? "TAMPERED" : `${ledger.seals} seal${ledger.seals === 1 ? "" : "s"}`}`}
        {` · ${active} active waiver${active === 1 ? "" : "s"}`}
      </span>
      <b>{open ? "−" : "+"}</b>
    </button>
    {open && <div className="fleet-body">
      {error && <div className="alert error">{error}</div>}
      {report && <div className="fleet-grid">
        <div className="exec-card"><h3>Fleet score</h3><div className="score-card" style={{ border: 0, padding: 0 }}><ScoreRing value={report.fleet_score.fleet_score} /><div><p>Across evaluated devices</p><strong>{report.violations.still_open} open · {report.violations.resolved} resolved</strong></div></div></div>
        <div className="exec-card"><h3>Trend</h3><TrendChart trend={report.fleet_score_trend} cycle={report.score_cycle} /><CadenceNote label="New violations per day" cycle={report.violation_cycle} /></div>
      </div>}
      <div className="exec-card"><h3>Blast radius · risk overlay</h3><RiskMapView token={token} /></div>
      <div className="decision-row fleet-links">
        <span className="source">{ledger ? `Ledger: ${ledger.events} events, ${ledger.sealed_events} sealed${verified === true ? ", chain verified" : ""}.` : "Ledger unavailable."} {active} active waiver{active === 1 ? "" : "s"}.</span>
        <span>
          <button className="secondary" onClick={() => onOpen("reports")}>Ledger &amp; waivers</button>{" "}
          <button className="secondary" onClick={() => onOpen("executive")}>Executive report</button>{" "}
          <button className="secondary" onClick={() => onOpen("inventory")}>Drift between devices</button>
          {role === "admin" && <>{" "}<button className="secondary" onClick={() => onOpen("learning")}>Learning queue</button></>}
        </span>
      </div>
    </div>}
  </section>;
}

function LedgerIntegrity({ token, role }: { token: string; role: Role }) {
  const [status, setStatus] = useState<LedgerStatus | null>(null);
  const [verification, setVerification] = useState<LedgerVerification | null>(null);
  const [message, setMessage] = useState("");
  const [ledgerError, setLedgerError] = useState("");
  const [busy, setBusy] = useState("");
  const refresh = () => getLedgerStatus(token).then(setStatus).catch((reason) => setLedgerError(reason instanceof Error ? reason.message : "Ledger unavailable"));
  useEffect(() => { refresh(); }, [token]);
  async function run(kind: "seal" | "verify") {
    setBusy(kind); setMessage(""); setLedgerError("");
    try {
      if (kind === "seal") { const result = await sealLedger(token); setMessage(result.sealed ? `Sealed ${result.sealed} event(s) as seal ${result.seq}.` : "Nothing new to seal."); }
      else setVerification(await verifyLedger(token));
      await refresh();
    } catch (reason) { setLedgerError(reason instanceof Error ? reason.message : "Request failed"); }
    finally { setBusy(""); }
  }
  return <div className="empty-card ledger-card">
    <p>Ledger integrity · signed Merkle seals</p>
    {status ? <>
      <span>{status.events} events · {status.sealed_events} sealed · {status.unsealed_events} waiting · {status.seals} seal{status.seals === 1 ? "" : "s"}{status.key_id ? ` · key ${status.key_id}` : ""}</span>
      {!status.signing_configured && <span className="source">No signing key is configured, so events cannot be sealed yet.</span>}
      {status.head && <code className="ledger-head">head #{status.head.seq} {status.head.hash.slice(0, 24)}…</code>}
    </> : null}
    {verification && <div className={`alert ${verification.ok ? "success" : "error"}`}>{verification.ok ? `Verified: ${verification.events_sealed} sealed events across ${verification.seals} seal(s) are intact.` : `TAMPERING DETECTED: ${verification.problems.map((p) => `seal ${p.seal} — ${p.detail}`).join("; ")}`}</div>}
    {message && <span className="source">{message}</span>}{ledgerError && <div className="alert error">{ledgerError}</div>}
    <div className="decision-row">
      <button className="secondary" disabled={!!busy || (status !== null && !status.signing_configured)} onClick={() => run("verify")}>{busy === "verify" ? "Verifying…" : "Verify ledger"}</button>
      {role === "admin" && <button className="primary" disabled={!!busy || !status?.signing_configured} onClick={() => run("seal")}>{busy === "seal" ? "Sealing…" : "Seal now"}</button>}
    </div>
  </div>;
}

function ReportsView({ audit, token, role }: { audit: AuditRun | null; token: string; role: Role }) {
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  async function openKind(kind: "download" | "json" | "cef") {
    if (!audit) return;
    setBusy(kind); setError("");
    try {
      if (kind === "download") {
        await generateReport(audit.id, token);
        // Live mode: generateReport only builds the report server-side; the PDF
        // still has to be fetched with the auth header and opened.
        if (!USE_MOCK) await openProtectedReport(audit.id, token, "download");
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
    <LedgerIntegrity token={token} role={role} />
    <WaiverRegister token={token} role={role} />
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
          <TrendChart trend={report.fleet_score_trend} cycle={report.score_cycle} />
          <CadenceNote label="New violations per day" cycle={report.violation_cycle} />
        </div>
      </section>

      <section className="exec-card">
        <h3>Blast radius topology · risk overlay</h3>
        <RiskMapView token={token} />
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
  const [findingQuery, setFindingQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<"ALL" | Severity>("ALL");
  // Starts "dark" to match the SSR fallback; the hydration effect below
  // immediately syncs it from the data-theme attribute the blocking script
  // in layout.tsx already set on <html> before this ever paints.
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [hydrated, setHydrated] = useState(false);
  useEffect(() => {
    setToken(readSession("na_token", "")); setEmail(readSession("na_email", ""));
    setRole(readSession("na_role", "admin" as Role));
    setAudit(readSession("na_audit", null));
    setInventory(readLocal("na_inventory", []));
    setRemediations(readSession("na_remediations", []));
    setSidebarCollapsed(readSession("na_sidebar_collapsed", false));
    setTheme(document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark");
    setHydrated(true);
  }, []);
  // Merge the server's evaluated runs into the browser-local inventory, so
  // history survives a cleared browser or a different machine.
  useEffect(() => {
    if (!hydrated || !token || USE_MOCK) return;
    let cancelled = false;
    (async () => {
      try {
        const ids = await listAuditRunIds(token);
        const runs = await Promise.all(ids.map((id) => getAudit(id, token).catch(() => null)));
        if (cancelled) return;
        setInventory((prev) => {
          const byId = new Map(prev.map((run) => [run.id, run]));
          runs.forEach((run) => { if (run) byId.set(run.id, run); });
          return [...byId.values()].sort((a, b) => b.created_at.localeCompare(a.created_at));
        });
      } catch { /* inventory stays browser-local if the server list is unavailable */ }
    })();
    return () => { cancelled = true; };
  }, [hydrated, token]);
  useEffect(() => {
    if (!hydrated) return;
    document.documentElement.setAttribute("data-theme", theme);
    writeLocal("na_theme", theme);
  }, [theme, hydrated]);
  // Guarded by `hydrated` so the fallback values above never overwrite the
  // real persisted state with blanks before the hydration effect runs.
  useEffect(() => { if (hydrated) writeLocal("na_inventory", inventory); }, [inventory, hydrated]);
  useEffect(() => { if (hydrated) writeSession("na_sidebar_collapsed", sidebarCollapsed); }, [sidebarCollapsed, hydrated]);
  useEffect(() => { if (hydrated) { writeSession("na_token", token); writeSession("na_email", email); } }, [token, email, hydrated]);
  useEffect(() => { if (hydrated) writeSession("na_audit", audit); }, [audit, hydrated]);
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
      setSelected(null);
      setInventory((prev) => [completed, ...prev.filter((item) => item.id !== completed.id)]);
      setNotice(run.status === "NEEDS_REVIEW" ? "No compliance verdict was issued: parsing evidence requires human review." : "Audit completed. Every verdict below was produced by version-controlled policy.");
    }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Upload failed"); }
    finally { setBusy(""); }
  }
  async function handleCollect(target: CollectTarget) {
    setBusy("upload"); setError(""); setNotice("Collecting the running configuration from the device…");
    try {
      const queued = await collectConfig(target, token);
      const run = await getAudit(queued.job_id, token);
      setAudit(run);
      setSelected(null);
      setInventory((prev) => [run, ...prev.filter((item) => item.id !== run.id)]);
      setNotice(run.status === "NEEDS_REVIEW" ? "No compliance verdict was issued: parsing evidence requires human review." : "Collected and audited. Every verdict below was produced by version-controlled policy.");
    }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Collection failed"); }
    finally { setBusy(""); }
  }
  async function handleFiles(files: FileList | null | undefined) {
    const list = Array.from(files ?? []);
    for (const file of list) await handleFile(file);
    if (list.length > 1) setNotice(`${list.length} configurations audited — compare them under Device inventory.`);
  }
  async function refreshAudit() {
    if (!audit) return;
    try {
      const fresh = await getAudit(audit.id, token);
      setAudit(fresh);
      setSelected((current) => current ? fresh.findings.find((f) => f.control_id === current.control_id) ?? null : null);
      setInventory((prev) => [fresh, ...prev.filter((item) => item.id !== fresh.id)]);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Could not refresh the audit"); }
  }
  function newAudit() {
    setAudit(null); setSelected(null); setRemediations([]); setError(""); setNotice(""); setBusy("");
  }
  function openFromInventory(run: AuditRun) {
    setAudit(run); setSelected(null); setRemediations([]); setError(""); setNotice(""); setView("workspace");
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

  const query = findingQuery.trim().toLowerCase();
  const visibleFindings = (audit?.findings ?? []).filter((finding) =>
    (severityFilter === "ALL" || finding.severity === severityFilter)
    && (!query || `${finding.control_id} ${finding.title} ${finding.evidence}`.toLowerCase().includes(query)));

  if (!token) return <Login onLogin={(newToken, userEmail, userRole) => { setToken(newToken); setEmail(userEmail); setRole(userRole); }} />;
  return <main className={`app-shell ${sidebarCollapsed ? "sidebar-collapsed" : ""}`}>
    <nav className="sidebar"><div className="sidebar-head"><div className="brand"><span className="brand-mark">N</span><span>NETAUDIT</span></div><div className="sidebar-actions"><button className="theme-toggle" onClick={() => setTheme((t) => (t === "dark" ? "light" : "dark"))} aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"} title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}>{theme === "dark" ? "☀" : "☾"}</button><button className="sidebar-toggle" onClick={() => setSidebarCollapsed((c) => !c)} aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"} title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}>{sidebarCollapsed ? "»" : "«"}</button></div></div><div className="nav-items"><button className={view === "workspace" ? "active" : ""} onClick={() => setView("workspace")}>⌁<span>Audit workspace</span></button><button className={view === "inventory" ? "active" : ""} onClick={() => setView("inventory")}>▦<span>Device inventory</span></button><button className={view === "learning" ? "active" : ""} onClick={() => setView("learning")}>◎<span>Learning queue</span></button><button className={view === "reports" ? "active" : ""} onClick={() => setView("reports")}>◫<span>Reports</span></button><button className={view === "executive" ? "active" : ""} onClick={() => setView("executive")}>◆<span>Executive report</span></button></div><div className="method-card"><span className="pulse" /><strong>Decision boundary active</strong><p>AI extracts. OPA decides.</p></div><div className="user"><span>{email.slice(0, 1).toUpperCase()}</span><div><strong>{email}</strong><small>{role.charAt(0).toUpperCase() + role.slice(1)}</small></div></div></nav>
    {view === "inventory" ? <DeviceInventory inventory={inventory} onSelect={openFromInventory} /> : view === "learning" ? <LearningQueue token={token} /> : view === "reports" ? <ReportsView audit={audit} token={token} role={role} /> : view === "executive" ? <ExecutiveReportView token={token} /> :
      <div className="workspace"><header><div><p className="eyebrow">SECURITY OPERATIONS</p><h1>Audit workspace</h1></div><div className="header-actions"><span className="airgap">● WORKS WITHOUT INTERNET</span><TimeBadge token={token} />{audit && <button className="secondary" onClick={newAudit} disabled={!!busy}>Upload new config</button>}{audit && <button className="secondary" onClick={report} disabled={!!busy}>{busy === "report" ? "Building report…" : "Download proof report"}</button>}</div></header>
        <FleetPosture token={token} role={role} onOpen={setView} refreshKey={audit?.id ?? ""} /><section className="plain-guide"><strong>How NetAudit works</strong><span><b>1</b> Upload configuration</span><span><b>2</b> See risks with proof</span><span><b>3</b> Review suggested fix</span><span><b>4</b> Export report</span></section>
        {notice && <div className="alert success">{notice}<button onClick={() => setNotice("")}>×</button></div>}{error && <div className="alert error">{error}<button onClick={() => setError("")}>×</button></div>}
        {!audit ? <section className="upload-stage"><div className="stage-copy"><p className="eyebrow">NEW ASSESSMENT</p><h2>Turn raw configuration into defensible evidence.</h2><p>Upload a Cisco or Fortinet text configuration. Secrets are redacted before immutable storage; compliance decisions remain deterministic.</p><div className="pipeline"><span>01<br /><b>Ingest</b></span><i /> <span>02<br /><b>Normalize</b></span><i /> <span>03<br /><b>Evaluate</b></span><i /> <span>04<br /><b>Remediate</b></span></div></div><label className={`dropzone ${dragging ? "dragging" : ""}`} onDragOver={(e) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={(e) => { e.preventDefault(); setDragging(false); handleFiles(e.dataTransfer.files); }}><input type="file" multiple accept=".cfg,.conf,.txt" onChange={(e) => { handleFiles(e.target.files); e.target.value = ""; }} /><span className="upload-icon">↥</span><strong>{busy === "upload" ? "Evaluating configuration…" : "Drop a configuration here"}</strong><p>or click to browse · one or several files · .cfg, .conf, .txt · max 10 MB each</p></label><CollectForm onCollect={handleCollect} busy={busy === "upload"} /></section> : <>
          {(audit.status_detail?.security_flags?.length ?? 0) > 0 && <div className="alert warning">Ingest gate: {audit.status_detail?.security_flags?.filter((f) => f.kind === "possible_prompt_injection").length ?? 0} line(s) that look like instructions to an AI and {audit.status_detail?.security_flags?.filter((f) => f.kind === "line_truncated").length ?? 0} over-long line(s) were neutralised before parsing. The original file is unchanged and the verdicts come from the remaining configuration.</div>}
          <section className="audit-head"><div><div className="status-line"><span className="status">{audit.status}</span><span>{audit.id}</span></div><h2>{audit.original_filename}</h2><div className="device-meta"><span>Vendor <b>{audit.device?.detected_vendor || "Detected"}</b></span><span>OS <b>{audit.device?.detected_os || "Unknown"}</b></span><span>Version <b>{audit.device?.detected_os_version || "Not in config"}</b></span><span>Model <b>{audit.device?.hardware_model || "Not in config"}</b></span><span>Serial <b>{audit.device?.serial_number || "Not in config"}</b></span><span>Parse confidence <b>{Math.round((audit.device?.parsing_confidence || 0) * 100)}%</b></span><AnomalyChip anomaly={audit.anomaly} /><span>Policy <b>{audit.policy_bundle_version || "cis-generic-level1@1.0.0"}</b></span><span>SHA-256 <b>{audit.file_hash.slice(0, 12)}…</b></span></div></div><div className="fix-actions"><button className="primary" onClick={remediationAction} disabled={!!busy}>{busy === "remediation" ? "Preflighting…" : remediations.length ? "Regenerate fixes" : "Generate safe fixes"}</button><TwinSummary remediations={remediations} /></div></section>
          <p className="eyebrow section-eyebrow">RISK SEVERITY ASSESSMENTS</p>
          <section className="metrics">{audit.summary.compliance_score !== null ? <div className="score-card"><ScoreRing value={audit.summary.control_pass_rate ?? audit.summary.compliance_score} /><div><p>Prototype checks passed</p><strong>{audit.summary.controls_passed ?? 0} of {audit.summary.controls_evaluated ?? 11} checks passed</strong><span>CIS-inspired demo rules · not a certification claim</span>{(audit.summary.waived ?? 0) > 0 && <span className="waived-note">{audit.summary.waived} waived (accepted risk) · score without waivers {audit.summary.score_without_waivers}</span>}<span className="verdict-badge" title="Every PASS/FAIL comes from version-controlled OPA/Rego rules; no language model is involved in the decision.">✓ DETERMINISTIC VERDICT · OPA POLICY {audit.policy_bundle_version || "cis-generic-level1@1.0.0"}</span></div></div> : <div className="empty-card"><p>Not yet evaluated.</p><span>Parsing evidence requires human review before a compliance score exists.</span></div>}{severityOrder.map((level) => <div className="metric" key={level}><span className={`dot ${level.toLowerCase()}`} /><p>{level}</p><strong>{audit.summary.by_severity[level] || 0}</strong></div>)}</section>
          <ConfidenceLedger device={audit.device} status={audit.status} />
          <TrustPanel runId={audit.id} token={token} />
          <section className="results-layout"><div className="findings"><div className="section-title"><div><p className="eyebrow">PASS / FAIL · RISK SEVERITY</p><h2>Findings</h2></div><span>{visibleFindings.length === audit.findings.length ? `${audit.findings.length} failed controls` : `${visibleFindings.length} of ${audit.findings.length} shown`}</span></div><div className="finding-filters"><input type="search" value={findingQuery} onChange={(e) => setFindingQuery(e.target.value)} placeholder="Filter by control, title or evidence" aria-label="Filter findings" /><select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value as "ALL" | Severity)} aria-label="Filter by severity"><option value="ALL">All severities</option>{severityOrder.map((level) => <option key={level} value={level}>{level}</option>)}</select></div><div className="finding-list">{visibleFindings.length === 0 && <p className="source" style={{ padding: "14px 17px" }}>No findings match this filter.</p>}{visibleFindings.map((finding) => { const proposal = remediations.find((item) => item.control_id === finding.control_id); return <button key={finding.control_id} className={selected?.control_id === finding.control_id ? "selected" : ""} onClick={() => setSelected(finding)}><span className={`severity ${finding.severity.toLowerCase()}`}>{finding.severity}</span><div><strong>{finding.title}</strong><p>{finding.control_id} · {finding.evidence}</p></div><span className="finding-state">{finding.waiver ? "WAIVED" : proposal?.applied_at ? "APPLIED" : proposal?.approval_status === "APPROVED" ? "✓ APPROVED" : proposal ? (proposal.preflight_status || proposal.preflight?.status) : "REVIEW"}</span><b>›</b></button>; })}</div><ControlResults results={audit.control_results} /></div></section>
          {selected && <FindingPanel finding={selected} remediation={selectedRemediation} device={{ hostname: audit.device?.hostname || audit.original_filename, vendor: audit.device?.detected_vendor || "Unrecognized", os: audit.device?.detected_os }} onDecision={decide} onApply={applyFix} onRollback={rollbackFix} onClose={() => setSelected(null)} onWaiverChange={refreshAudit} busy={busy === "decision"} runId={audit.id} token={token} role={role} />}
        </>}
      </div>}
  </main>;
}
