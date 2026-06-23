"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import type { FilterOptions, UseCase } from "../lib/api";

const TACTIC_ORDER = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution",
  "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Discovery", "Lateral Movement", "Collection", "Command and Control",
  "Exfiltration", "Impact",
];

function level(count: number) {
  if (count >= 16) return 5;
  if (count >= 8) return 4;
  if (count >= 4) return 3;
  if (count >= 2) return 2;
  if (count >= 1) return 1;
  return 0;
}

export default function MitreMatrix({
  useCases, filters, initialTactic = "",
}: {
  useCases: UseCase[];
  filters: FilterOptions;
  initialTactic?: string;
}) {
  const [q, setQ] = useState("");
  const [tactic, setTactic] = useState(initialTactic);
  const [product, setProduct] = useState("");
  const [source, setSource] = useState("");
  const [severity, setSeverity] = useState("");

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return useCases.filter((uc) => {
      if (product && !uc.products.includes(product)) return false;
      if (source && !uc.sources.includes(source)) return false;
      if (severity && !(uc.severities?.[severity] > 0)) return false;
      if (needle) {
        const hay = `${uc.technique_id || ""} ${uc.name}`.toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    });
  }, [useCases, q, product, source, severity]);

  // tactic -> sorted cells
  const columns = useMemo(() => {
    const byTactic = new Map<string, UseCase[]>();
    for (const t of TACTIC_ORDER) byTactic.set(t, []);
    for (const uc of filtered) {
      const tacs = uc.tactics.length ? uc.tactics : ["Unmapped"];
      for (const t of tacs) {
        if (!byTactic.has(t)) byTactic.set(t, []);
        byTactic.get(t)!.push(uc);
      }
    }
    for (const list of byTactic.values()) list.sort((a, b) => b.rule_count - a.rule_count);
    return byTactic;
  }, [filtered]);

  const visibleTactics = tactic ? [tactic] : Array.from(columns.keys());

  // summary
  const coveredTactics = TACTIC_ORDER.filter((t) => (columns.get(t)?.length || 0) > 0).length;
  const coveredTechniques = new Set(filtered.map((uc) => uc.technique_id || uc.id)).size;
  const totalDetections = filtered.reduce((s, uc) => s + uc.rule_count, 0);

  return (
    <>
      {/* summary */}
      <section className="cards four-cards">
        <div className="card stat-card">
          <div className="stat-label">Tactics Covered</div>
          <div className="kpi">{coveredTactics}<span className="faint" style={{ fontSize: 18 }}> / 14</span></div>
          <div className="muted">ATT&CK kill chain</div>
        </div>
        <div className="card stat-card">
          <div className="stat-label">Techniques</div>
          <div className="kpi">{coveredTechniques.toLocaleString()}</div>
          <div className="muted">with at least one detection</div>
        </div>
        <div className="card stat-card">
          <div className="stat-label">Detections Mapped</div>
          <div className="kpi">{totalDetections.toLocaleString()}</div>
          <div className="muted">in current view</div>
        </div>
        <div className="card stat-card">
          <div className="stat-label">Use Cases</div>
          <div className="kpi">{filtered.length.toLocaleString()}</div>
          <div className="muted">technique groupings</div>
        </div>
      </section>

      {/* filters */}
      <section className="card">
        <div className="filter-grid">
          <label className="field span-2"><span>Search techniques</span>
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="T1059, PowerShell, credential dumping…" />
          </label>
          <label className="field"><span>Tactic</span>
            <select value={tactic} onChange={(e) => setTactic(e.target.value)}>
              <option value="">All tactics</option>
              {TACTIC_ORDER.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </label>
          <label className="field"><span>Product</span>
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
          <label className="field"><span>Severity</span>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">Any severity</option>
              {filters.severities.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          <div className="field" style={{ justifyContent: "flex-end" }}>
            <span>&nbsp;</span>
            <div className="matrix-legend">
              <span>Low</span>
              <span className="legend-scale">
                <i className="lvl-1" /><i className="lvl-2" /><i className="lvl-3" /><i className="lvl-4" /><i className="lvl-5" />
              </span>
              <span>High</span>
            </div>
          </div>
        </div>
      </section>

      {/* matrix */}
      <section className="card">
        {filtered.length === 0 ? (
          <div className="empty">
            <h3>No techniques match these filters</h3>
            <p>Adjust or clear the filters above to see coverage across the ATT&CK matrix.</p>
          </div>
        ) : (
          <div className="matrix-board">
            {visibleTactics.map((t) => {
              const cells = columns.get(t) || [];
              const colDetections = cells.reduce((s, c) => s + c.rule_count, 0);
              return (
                <div className="matrix-col" key={t}>
                  <div className="matrix-col-head">
                    <strong>{t}</strong>
                    <div className="col-meta">
                      <span>{cells.length} tech</span>
                      <span>{colDetections} det</span>
                    </div>
                  </div>
                  {cells.length === 0 ? (
                    <div className="matrix-empty">No coverage</div>
                  ) : (
                    cells.map((uc) => (
                      <Link
                        key={`${t}-${uc.id}`}
                        href={`/use-cases?focus=${encodeURIComponent(uc.technique_id || uc.id)}`}
                        className={`matrix-cell lvl-${level(uc.rule_count)}`}
                      >
                        <div className="cell-id">{uc.technique_id || "—"}</div>
                        <div className="cell-name">{uc.name}</div>
                        <div className="cell-count">{uc.rule_count} detection{uc.rule_count === 1 ? "" : "s"}</div>
                      </Link>
                    ))
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>
    </>
  );
}
