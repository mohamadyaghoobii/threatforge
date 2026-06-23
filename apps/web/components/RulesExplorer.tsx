"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import type { FilterOptions, RuleListItem } from "../lib/api";
import { IconWarn, IconArrow } from "./icons";

function qualityColor(score: number) {
  if (score >= 75) return "var(--emerald)";
  if (score >= 50) return "var(--blue)";
  if (score >= 30) return "var(--high)";
  return "var(--crit)";
}

function SeverityBadge({ severity }: { severity: string | null }) {
  const s = (severity || "unknown").toLowerCase();
  return <span className={`sev sev-${s}`}>{s}</span>;
}

const RENDER_CAP = 300;

export default function RulesExplorer({
  rules, filters, total, initialQuery = "",
}: {
  rules: RuleListItem[];
  filters: FilterOptions;
  total: number;
  initialQuery?: string;
}) {
  const [q, setQ] = useState(initialQuery);
  const [severity, setSeverity] = useState("");
  const [product, setProduct] = useState("");
  const [source, setSource] = useState("");
  const [tactic, setTactic] = useState("");
  const [onlyFlagged, setOnlyFlagged] = useState(false);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rules.filter((r) => {
      if (severity && (r.severity || "").toLowerCase() !== severity.toLowerCase()) return false;
      if (product && r.product !== product) return false;
      if (source && r.source_repo !== source) return false;
      if (tactic && !r.mitre_tactics.includes(tactic)) return false;
      if (onlyFlagged && !(r.quality_score < 40 || r.mitre_techniques.length === 0)) return false;
      if (needle) {
        const hay = [r.title, r.source_repo, r.product, r.service, r.category, ...r.mitre_techniques]
          .filter(Boolean).join(" ").toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    });
  }, [rules, q, severity, product, source, tactic, onlyFlagged]);

  const shown = filtered.slice(0, RENDER_CAP);

  function reset() {
    setQ(""); setSeverity(""); setProduct(""); setSource(""); setTactic(""); setOnlyFlagged(false);
  }

  return (
    <>
      <section className="card">
        <div className="filter-grid">
          <label className="field span-2"><span>Search detections</span>
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Title, technique, product, source…" />
          </label>
          <label className="field"><span>Severity</span>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">All</option>
              {filters.severities.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          <label className="field"><span>Product / log source</span>
            <select value={product} onChange={(e) => setProduct(e.target.value)}>
              <option value="">All products</option>
              {filters.products.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </label>
          <label className="field"><span>Source</span>
            <select value={source} onChange={(e) => setSource(e.target.value)}>
              <option value="">All sources</option>
              {filters.sources.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          <label className="field"><span>MITRE tactic</span>
            <select value={tactic} onChange={(e) => setTactic(e.target.value)}>
              <option value="">All tactics</option>
              {filters.tactics.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </label>
          <div className="field" style={{ alignSelf: "end" }}>
            <span>&nbsp;</span>
            <label className="field" style={{ flexDirection: "row", alignItems: "center", gap: 8, cursor: "pointer" }}>
              <input type="checkbox" checked={onlyFlagged} onChange={(e) => setOnlyFlagged(e.target.checked)} style={{ width: 16 }} />
              <span style={{ whiteSpace: "nowrap" }}>Flagged only</span>
            </label>
          </div>
        </div>
      </section>

      <section className="card">
        <div className="card-head">
          <h3>Detections</h3>
          <div className="badge-row">
            <span className="muted">{filtered.length.toLocaleString()} match{filtered.length === 1 ? "" : "es"} of {total.toLocaleString()}</span>
            <button className="button ghost sm" type="button" onClick={reset}>Reset</button>
          </div>
        </div>

        {filtered.length === 0 ? (
          <div className="empty">
            <h3>No detections match</h3>
            <p>Try a broader search or clear a filter. The library has {total.toLocaleString()} normalized detections.</p>
          </div>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Detection</th>
                  <th>Severity</th>
                  <th>Quality</th>
                  <th>Telemetry</th>
                  <th>ATT&CK</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {shown.map((rule) => {
                  const flagged = rule.quality_score < 40 || rule.mitre_techniques.length === 0;
                  return (
                    <tr key={rule.id}>
                      <td>
                        <Link className="link" href={`/rules/${rule.id}`}>{rule.title}</Link>
                        <div className="faint" style={{ fontSize: 11.5, marginTop: 3 }}>
                          {rule.source_repo}
                          {flagged && (
                            <span className="flag" style={{ marginLeft: 10 }}>
                              <IconWarn />{rule.mitre_techniques.length === 0 ? "no ATT&CK mapping" : "low quality"}
                            </span>
                          )}
                        </div>
                      </td>
                      <td><SeverityBadge severity={rule.severity} /></td>
                      <td>
                        <div className="quality">
                          <span className="quality-track">
                            <span className="quality-fill" style={{ width: `${rule.quality_score}%`, background: qualityColor(rule.quality_score) }} />
                          </span>
                          <span className="quality-num" style={{ color: qualityColor(rule.quality_score) }}>{rule.quality_score}</span>
                        </div>
                      </td>
                      <td>
                        <div className="badge-row">
                          {[rule.product, rule.service, rule.category].filter(Boolean).slice(0, 3).map((item, i) => (
                            <span className="badge soft" key={`${item}-${i}`}>{item}</span>
                          ))}
                          {![rule.product, rule.service, rule.category].some(Boolean) && <span className="faint small-text">—</span>}
                        </div>
                      </td>
                      <td>
                        <div className="badge-row">
                          {rule.mitre_techniques.slice(0, 3).map((t) => <span className="badge" key={t}>{t}</span>)}
                          {rule.mitre_techniques.length > 3 && <span className="count-chip">+{rule.mitre_techniques.length - 3}</span>}
                          {rule.mitre_techniques.length === 0 && <span className="faint small-text">—</span>}
                        </div>
                      </td>
                      <td><Link className="link" href={`/rules/${rule.id}`} aria-label="Open detection"><IconArrow /></Link></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {filtered.length > RENDER_CAP && (
          <div className="muted small-text" style={{ marginTop: 12 }}>
            Showing first {RENDER_CAP} of {filtered.length.toLocaleString()} — refine filters to narrow the result set.
          </div>
        )}
      </section>
    </>
  );
}
