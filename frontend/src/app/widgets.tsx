"use client";

import { useEffect, useState } from "react";
import { getFleetTopology, getSimilarMappings } from "../lib/api";
import type { AuditRun, RiskMap, ScoreCycle, SimilarMappings } from "../lib/types";

type TrendPoint = { evaluated_at: string; fleet_score: number };

export function TrendChart({ trend, cycle }: { trend: TrendPoint[]; cycle?: ScoreCycle }) {
  if (trend.length < 2) return <p className="muted">Not enough history yet — at least two evaluations are needed for a trend.</p>;
  const W = 560, H = 210, pad = { l: 34, r: 14, t: 14, b: 26 };
  const times = trend.map((p) => new Date(p.evaluated_at).getTime());
  const tMin = Math.min(...times), tMax = Math.max(...times, tMin + 1);
  const scores = trend.map((p) => p.fleet_score);
  const lo = Math.max(0, Math.floor((Math.min(...scores, ...(cycle?.markers.map((m) => m.score) ?? [])) - 5) / 10) * 10), hi = 100;
  const x = (t: number) => pad.l + ((t - tMin) / (tMax - tMin)) * (W - pad.l - pad.r);
  const y = (score: number) => pad.t + ((hi - score) / (hi - lo)) * (H - pad.t - pad.b);
  const line = trend.map((p, i) => `${i === 0 ? "M" : "L"}${x(times[i]).toFixed(1)},${y(p.fleet_score).toFixed(1)}`).join(" ");
  const ticks = [lo, Math.round((lo + hi) / 2), hi];
  const markers = (cycle?.detected ? cycle.markers : []).map((m) => ({ ...m, t: new Date(`${m.date}T12:00:00`).getTime() })).filter((m) => m.t >= tMin - 864e5 && m.t <= tMax + 864e5);
  return <div className="trend-chart">
    <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Fleet compliance score over time">
      {ticks.map((tick) => <g key={tick}><line className="trend-grid" x1={pad.l} x2={W - pad.r} y1={y(tick)} y2={y(tick)} /><text className="trend-axis" x={pad.l - 6} y={y(tick) + 3} textAnchor="end">{tick}</text></g>)}
      <path className="trend-line" d={line} fill="none" />
      {trend.map((p, i) => <circle key={i} className="trend-dot" cx={x(times[i])} cy={y(p.fleet_score)} r={3}><title>{new Date(p.evaluated_at).toLocaleString()} · {p.fleet_score}/100</title></circle>)}
      {markers.map((m) => {
        const cx = Math.min(W - pad.r, Math.max(pad.l, x(m.t))), cy = y(m.score);
        return <g key={m.date} className="trend-marker" transform={`translate(${cx},${cy - 12})`}>
          <polygon points="0,-8 8,6 -8,6" /><text x="0" y="4" textAnchor="middle">!</text>
          <title>DFT frequency anomaly detected — {m.date}: {Math.abs(m.deviation)} points below the trend in a recurring {Math.round(cycle?.period_days ?? 0)}-day cycle</title>
        </g>;
      })}
      <text className="trend-axis" x={pad.l} y={H - 6}>{new Date(tMin).toLocaleDateString()}</text>
      <text className="trend-axis" x={W - pad.r} y={H - 6} textAnchor="end">{new Date(tMax).toLocaleDateString()}</text>
    </svg>
    <p className="source">{cycle?.detected ? `⚠ ${cycle.note} Found by a discrete Fourier transform over ${cycle.days_analysed} days; ${cycle.markers.length} low points marked.` : `Frequency analysis (DFT): ${cycle?.note ?? "not run"}`}</p>
  </div>;
}

const scoreColour = (score: number | null) => score === null ? "var(--dim)" : score >= 80 ? "var(--score-good)" : score >= 50 ? "var(--score-mid)" : "var(--score-bad)";

export function RiskMapView({ token }: { token: string }) {
  const [map, setMap] = useState<RiskMap | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => { getFleetTopology(token).then(setMap).catch(() => setFailed(true)); }, [token]);
  if (failed) return <p className="source">Topology service unavailable.</p>;
  if (!map) return <p className="source">Loading topology…</p>;
  if (map.nodes.length === 0) return <p className="source">{map.note || "No routing topology is known yet. It is built from audited devices that peer with each other (requires Neo4j)."}</p>;
  const W = 560, H = 290, cx = W / 2, cy = H / 2, radius = 105;
  const h = map.highlight;
  const pos = new Map<string, { x: number; y: number }>();
  const others = map.nodes.filter((n) => n.id !== h?.core);
  if (h?.core) pos.set(h.core, { x: cx, y: cy });
  others.forEach((n, i) => { const a = (2 * Math.PI * i) / others.length - Math.PI / 2; pos.set(n.id, { x: cx + radius * 1.35 * Math.cos(a), y: cy + radius * Math.sin(a) }); });
  const onPath = new Set(h?.path ?? []);
  const pathEdge = (s: string, t: string) => { const p = h?.path; if (!p) return false; for (let i = 0; i < p.length - 1; i += 1) if ((p[i] === s && p[i + 1] === t) || (p[i] === t && p[i + 1] === s)) return true; return false; };
  return <div className="risk-map">
    <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Routing topology with risk overlay">
      <defs><filter id="risk-glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="3.5" result="blur" /><feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge></filter></defs>
      {map.edges.map((e, i) => { const a = pos.get(e.source), b = pos.get(e.target); if (!a || !b) return null; const hot = pathEdge(e.source, e.target);
        return <line key={i} className={hot ? "risk-edge hot" : "risk-edge"} x1={a.x} y1={a.y} x2={b.x} y2={b.y} filter={hot ? "url(#risk-glow)" : undefined}><title>{e.protocol || "routes to"}</title></line>; })}
      {map.nodes.map((n) => { const p = pos.get(n.id); if (!p) return null; const entry = n.id === h?.entry_point, core = n.id === h?.core;
        return <g key={n.id} transform={`translate(${p.x},${p.y})`} className={`risk-node ${n.kind} ${entry ? "entry" : ""} ${onPath.has(n.id) ? "on-path" : ""}`}>
          <circle r={core ? 15 : 11} fill={entry ? "var(--critical)" : n.kind === "unresolved" ? "transparent" : scoreColour(n.compliance_score)} filter={entry ? "url(#risk-glow)" : undefined} />
          <text y={core ? 29 : 25} textAnchor="middle">{n.label}</text>
          <title>{n.kind === "unresolved" ? `Not yet audited · ${n.label}` : `${n.label} · score ${n.compliance_score ?? "n/a"} · ${n.findings ?? "n/a"} findings · ${n.connections} link(s)${entry ? " · weakest posture (entry point)" : ""}${core ? " · most-connected (core)" : ""}`}</title>
        </g>; })}
    </svg>
    <p className="source">{h?.path ? `Shortest routing path from the weakest device to the core: ${h.path.map((id) => map.nodes.find((n) => n.id === id)?.label ?? id).join(" → ")} (${h.path.length - 1} hop${h.path.length === 2 ? "" : "s"}). Found by graph traversal over the real topology — a structural exposure path, not a prediction.` : map.note}</p>
    {map.control && <ContainmentPanel control={map.control} map={map} />}
    <p className="source"><span className="legend-dot" style={{ background: "var(--critical)" }} /> weakest posture <span className="legend-dot" style={{ background: "var(--score-good)" }} /> ≥80 <span className="legend-dot" style={{ background: "var(--score-mid)" }} /> 50–79 <span className="legend-dot" style={{ background: "var(--score-bad)" }} /> &lt;50 <span className="legend-dot hollow" /> not yet audited</p>
  </div>;
}

function ContainmentPanel({ control, map }: { control: NonNullable<RiskMap["control"]>; map: RiskMap }) {
  const label = (id: string) => map.nodes.find((n) => n.id === id)?.label ?? id.slice(0, 8);
  return <div className="containment">
    <p className="source"><b>State-space reachability</b> · x[k+1] = x[k] ∨ Aᵀx[k], starting from the weakest device</p>
    <div className="reach-steps">{control.reach_by_step.map((s) => <div key={s.step} className="reach-step" title={s.devices.map(label).join(", ")}>
      <span>k={s.step}</span><div className="reach-bar"><i style={{ width: `${(s.total / Math.max(control.devices, 1)) * 100}%` }} /></div><span>{s.total}/{control.devices}</span>
    </div>)}</div>
    <p className="source">The state stops changing at step {control.converged_at_step} ({control.reachable} of {control.devices} devices reached).{control.core_reachable ? ` The core is reached at step ${control.steps_to_core}.` : " The core is not reachable from the weakest device."}</p>
    {control.min_cut && control.core_reachable && <p className="source"><b>Containment:</b> filtering {control.min_cut.size} link{control.min_cut.size === 1 ? "" : "s"} ({control.min_cut.links.map((l) => `${label(l[0])}–${label(l[1])}`).join(", ")}) would cut the core off; fewer cannot, because that many link-disjoint paths exist.</p>}
  </div>;
}

type Stage = { name: string; detail: string; state: "ok" | "warn" | "none"; value: string };

export function VerificationPipeline({ device, status }: { device?: AuditRun["device"]; status: string }) {
  const agreement = device?.parser_agreement, fidelity = device?.reverse_translation_fidelity, confidence = device?.parsing_confidence;
  const stages: Stage[] = [
    { name: "Extraction", detail: "language model reads the configuration", state: confidence == null ? "none" : status === "NEEDS_REVIEW" ? "warn" : "ok", value: confidence == null ? "not measured" : `${Math.round(confidence * 100)}% confidence` },
    { name: "Cross-check", detail: "independent deterministic parser", state: agreement == null ? "none" : agreement >= 0.9 ? "ok" : "warn", value: agreement == null ? "not available for this vendor" : `${Math.round(agreement * 100)}% agreement` },
    { name: "Reverse check", detail: "CLI rebuilt from the result and compared", state: fidelity == null ? "none" : fidelity >= 0.7 ? "ok" : "warn", value: fidelity == null ? "not measured" : `${Math.round(fidelity * 100)}% fidelity` },
    { name: "Policy verdict", detail: "deterministic OPA rules, no model", state: status === "EVALUATED" || status === "COMPLETE" ? "ok" : status === "NEEDS_REVIEW" ? "warn" : "none", value: status === "EVALUATED" || status === "COMPLETE" ? "verdict issued" : status === "NEEDS_REVIEW" ? "held for human review" : "pending" },
  ];
  return <div className="pipeline-panel">
    <p className="eyebrow">VERIFICATION PIPELINE</p>
    <div className="pipeline-stages">{stages.map((s) => <div key={s.name} className={`pipe-stage ${s.state}`} title={s.detail}>
      <span className="pipe-mark">{s.state === "ok" ? "✓" : s.state === "warn" ? "!" : "–"}</span>
      <div><strong>{s.name}</strong><span>{s.value}</span></div>
    </div>)}</div>
    <p className="source">A checkmark appears only for a check that ran and passed its threshold. A model never makes the compliance decision.</p>
  </div>;
}

export function SimilarityPlot({ blockId, token }: { blockId: string; token: string }) {
  const [data, setData] = useState<SimilarMappings | null>(null);
  const [state, setState] = useState<"idle" | "loading" | "error">("idle");
  const [message, setMessage] = useState("");
  async function load() {
    setState("loading");
    try { setData(await getSimilarMappings(blockId, token)); setState("idle"); }
    catch (reason) { setState("error"); setMessage(reason instanceof Error ? reason.message : "Could not compare"); }
  }
  const W = 360, H = 230, m = 22;
  const px = (v: number) => m + ((v + 1) / 2) * (W - 2 * m), py = (v: number) => m + ((1 - (v + 1) / 2)) * (H - 2 * m);
  const best = data?.best ? data.points.find((p) => p.id === data.best!.id) : undefined;
  return <div className="similarity-box">
    <button type="button" className="secondary" onClick={load} disabled={state === "loading"}>{state === "loading" ? "Comparing…" : data ? "Refresh comparison" : "Why this category? Compare with taught mappings"}</button>
    {state === "error" && <p className="source">{message}</p>}
    {data && (data.query === null ? <p className="source">{data.note}</p> : <>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Embedding-space comparison">
        <rect className="sim-frame" x={m} y={m} width={W - 2 * m} height={H - 2 * m} rx={4} />
        {best && <line className="sim-link" x1={px(data.query.x)} y1={py(data.query.y)} x2={px(best.x)} y2={py(best.y)} />}
        {data.points.map((p) => <circle key={p.id} className={`sim-known ${p.id === data.best?.id ? "best" : ""}`} cx={px(p.x)} cy={py(p.y)} r={p.id === data.best?.id ? 6 : 4.5}><title>{p.field ?? "mapping"} = {p.value ?? ""} · cosine similarity {p.similarity.toFixed(2)}{p.cli_pattern ? ` · "${p.cli_pattern}"` : ""}</title></circle>)}
        <circle className="sim-pulse" cx={px(data.query.x)} cy={py(data.query.y)} r={6} />
        <circle className="sim-query" cx={px(data.query.x)} cy={py(data.query.y)} r={6}><title>This unrecognised block</title></circle>
      </svg>
      <p className="source"><span className="legend-dot sim-q" /> this block <span className="legend-dot sim-k" /> mappings humans already confirmed. Distance in the plot is a 2-D projection of the embeddings; the similarity numbers are exact.</p>
      {data.best && <p className="sim-best">Closest confirmed mapping: <b>{data.best.field}</b>{data.best.value ? ` = ${data.best.value}` : ""} · <b>Cosine similarity: {data.best.similarity.toFixed(2)}</b></p>}
      {data.points.slice(0, 3).map((p) => <p key={p.id} className="source">{p.similarity.toFixed(2)} · {p.field} {p.value ? `= ${p.value}` : ""}{p.cli_pattern ? ` · from “${p.cli_pattern}”` : ""}</p>)}
    </>)}
  </div>;
}
