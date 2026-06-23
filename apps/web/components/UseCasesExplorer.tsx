"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import type { FilterOptions, UseCase } from "../lib/api";
import { IconTerminal, IconArrow } from "./icons";

const SEV_ORDER = ["critical", "high", "medium", "low", "informational", "unknown"];
const SEV_COLOR: Record<string, string> = {
  critical: "var(--crit)", high: "var(--high)", medium: "var(--med)",
  low: "var(--low)", informational: "var(--info)", unknown: "var(--info)",
};

function SeverityStrip({ severities }: { severities: Record<string, number> }) {
  const total = Object.values(severities).reduce((a, b) => a + b, 0);
  if (!total) return null;
  return (
    <div style={{ display: "flex", height: 6, borderRadius: 999, overflow: "hidden", background: "rgba(120,150,190,0.12)" }}>
      {SEV_ORDER.map((s) => {
        const n = severities[s] || 0;
        if (!n) return null;
        return <span key={s} title={`${s}: ${n}`} style={{ width: `${(n / total) * 100}%`, background: SEV_COLOR[s] }} />;
      })}
    </div>
  );
}

export default function UseCasesExplorer({
  useCases, filters, focus = "",
}: {
  useCases: UseCase[];
  filters: FilterOptions;
  focus?: string;
}) {
  const [q, setQ] = useState(focus);
  const [tactic, setTactic] = useState("");
  const [product, setProduct] = useState("");
  const [source, setSource] = useState("");
  const [sort, setSort] = useState<"coverage" | "quality" | "id">("coverage");

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const out = useCases.filter((uc) => {
      if (tactic && !uc.tactics.includes(tactic)) return false;
      if (product && !uc.products.includes(product)) return false;
      if (source && !uc.sources.includes(source)) return false;
      if (needle) {
        const hay = `${uc.technique_id || ""} ${uc.name} ${uc.tactics.join(" ")}`.toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    });
    out.sort((a, b) => {
      if (sort === "coverage") return b.rule_count - a.rule_count;
      if (sort === "quality") return b.best_quality_score - a.best_quality_score;
      return (a.technique_id || a.id).localeCompare(b.technique_id || b.id);
    });
    return out;
  }, [useCases, q, tactic, product, source, sort]);

  return (
    <>
      <section className="card">
        <div className="filter-grid">
          <label className="field span-2"><span>Search use cases</span>
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Technique id, name, tactic…" />
          </label>
          <label className="field"><span>Tactic</span>
            <select value={tactic} onChange={(e) => setTactic(e.target.value)}>
              <option value="">All tactics</option>{filters.tactics.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </label>
          <label className="field"><span>Product</span>
            <select value={product} onChange={(e) => setProduct(e.target.value)}>
              <option value="">All products</option>{filters.products.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </label>
          <label className="field"><span>Source</span>
            <select value={source} onChange={(e) => setSource(e.target.value)}>
              <option value="">All sources</option>{filters.sources.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          <label className="field"><span>Sort by</span>
            <select value={sort} onChange={(e) => setSort(e.target.value as typeof sort)}>
              <option value="coverage">Coverage (detections)</option>
              <option value="quality">Best quality</option>
              <option value="id">Technique id</option>
            </select>
          </label>
        </div>
      </section>

      <div className="muted small-text" style={{ margin: "-4px 2px 0" }}>
        {filtered.length.toLocaleString()} use case{filtered.length === 1 ? "" : "s"}
      </div>

      {filtered.length === 0 ? (
        <div className="card"><div className="empty"><h3>No use cases match</h3><p>Adjust the filters to explore the detection library by ATT&CK technique.</p></div></div>
      ) : (
        <section className="cards" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))" }}>
          {filtered.slice(0, 120).map((uc) => (
            <div className="card" key={uc.id} style={{ display: "grid", gap: 10 }}>
              <div className="usecase-head">
                <strong style={{ fontSize: 15 }}>{uc.technique_id || uc.name}</strong>
                <span className="count-chip">{uc.rule_count} det</span>
              </div>
              {uc.technique_id && <div className="muted small-text" style={{ margin: 0 }}>{uc.name}</div>}
              <div className="badge-row">
                {uc.tactics.slice(0, 3).map((t) => <span className="badge soft" key={t}>{t}</span>)}
                {uc.tactics.length === 0 && <span className="faint small-text">Unmapped</span>}
              </div>
              <SeverityStrip severities={uc.severities} />
              <div className="kv" style={{ borderBottom: "none", padding: "4px 0 0" }}>
                <span className="k">Best quality</span>
                <span className="v">{uc.best_quality_score} / 100</span>
              </div>
              <div className="badge-row">
                {uc.target_support.slice(0, 4).map((t) => <span className="badge tech" key={t}>{t}</span>)}
              </div>
              <div className="result-header" style={{ marginTop: 2 }}>
                <span className="faint small-text" style={{ margin: 0 }}>{uc.products.slice(0, 2).join(", ") || "—"}</span>
                <Link className="button secondary sm" href={`/convert?technique=${encodeURIComponent(uc.technique_id || uc.id)}`}>
                  <IconTerminal /> Generate
                </Link>
              </div>
            </div>
          ))}
        </section>
      )}
      {filtered.length > 120 && (
        <div className="muted small-text">Showing first 120 of {filtered.length.toLocaleString()} — refine filters to narrow.</div>
      )}
    </>
  );
}
