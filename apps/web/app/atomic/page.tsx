"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { apiBase } from "../../lib/api";
import PageHeader from "../../components/PageHeader";
import { IconCrosshair, IconDashboard } from "../../components/icons";

type Technique = { technique_id: string; technique_name: string; test_count: number; platforms: string[] };
type AtomicTest = {
  id: number; technique_id: string; technique_name: string; test_name: string;
  description: string; platforms: string[]; executor: string; elevation_required: boolean;
  command: string; guid: string;
};
type Stats = { tests: number; techniques: number; by_executor: Record<string, number>; by_platform: Record<string, number> };

export default function AtomicPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [techs, setTechs] = useState<Technique[]>([]);
  const [q, setQ] = useState("");
  const [platform, setPlatform] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [tests, setTests] = useState<AtomicTest[]>([]);
  const [copiedGuid, setCopiedGuid] = useState<string | null>(null);

  useEffect(() => {
    fetch(`${apiBase}/api/atomic/stats`, { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => d && setStats(d));
  }, []);

  useEffect(() => {
    const p = new URLSearchParams();
    if (q.trim()) p.set("q", q.trim());
    if (platform) p.set("platform", platform);
    fetch(`${apiBase}/api/atomic/techniques?${p.toString()}`, { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => {
        setTechs(d);
        if (d.length && (!selected || !d.some((t: Technique) => t.technique_id === selected))) {
          setSelected(d[0].technique_id);
        }
      });
    // eslint-disable-next-line
  }, [q, platform]);

  useEffect(() => {
    if (!selected) return;
    fetch(`${apiBase}/api/atomic/techniques/${selected}/tests`, { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : []))
      .then(setTests);
  }, [selected]);

  const selectedTech = useMemo(() => techs.find((t) => t.technique_id === selected), [techs, selected]);

  async function copy(text: string, guid: string) {
    await navigator.clipboard.writeText(text);
    setCopiedGuid(guid);
    window.setTimeout(() => setCopiedGuid(null), 1500);
  }

  return (
    <div className="grid">
      <PageHeader
        eyebrow="Atomic Red Team"
        icon={<IconCrosshair />}
        title="Adversary Emulation"
        sub="A condensed, searchable digest of Atomic Red Team — every ATT&CK technique with its key tests, platforms, executor, and command, trimmed to the essentials for detection validation."
        actions={<Link className="button secondary" href="/dashboards"><IconDashboard /> Build Dashboard</Link>}
      />

      <section className="cards four-cards">
        <div className="card stat-card"><div className="stat-label">Techniques</div><div className="kpi">{stats?.techniques ?? 0}</div><div className="muted">covered by atomics</div></div>
        <div className="card stat-card"><div className="stat-label">Atomic tests</div><div className="kpi">{(stats?.tests ?? 0).toLocaleString()}</div><div className="muted">condensed procedures</div></div>
        <div className="card stat-card"><div className="stat-label">Executors</div><div className="kpi">{Object.keys(stats?.by_executor || {}).length}</div><div className="muted">shells / runners</div></div>
        <div className="card stat-card"><div className="stat-label">Platforms</div><div className="kpi">{Object.keys(stats?.by_platform || {}).length}</div><div className="muted">OS coverage</div></div>
      </section>

      <section className="card">
        <div className="filter-grid">
          <label className="field span-2"><span>Search techniques &amp; tests</span>
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="T1059, PowerShell, mimikatz, scheduled task..." />
          </label>
          <label className="field"><span>Platform</span>
            <select value={platform} onChange={(e) => setPlatform(e.target.value)}>
              <option value="">All platforms</option>
              {Object.keys(stats?.by_platform || {}).map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </label>
          <div className="field"><span>&nbsp;</span><div className="muted" style={{ paddingTop: 10 }}>{techs.length} techniques</div></div>
        </div>
      </section>

      <section className="cards generator-layout">
        <section className="card form-grid">
          <h3>Techniques</h3>
          <div className="usecase-list">
            {techs.slice(0, 400).map((t) => (
              <button key={t.technique_id} type="button"
                className={t.technique_id === selected ? "usecase-item active" : "usecase-item"}
                onClick={() => setSelected(t.technique_id)}>
                <div className="usecase-head">
                  <strong>{t.technique_id}</strong>
                  <span className="count-chip">{t.test_count} tests</span>
                </div>
                <div className="muted small-text">{t.technique_name}</div>
                <div className="badge-row" style={{ marginTop: 6 }}>
                  {t.platforms.slice(0, 4).map((p) => <span key={p} className="badge soft">{p}</span>)}
                </div>
              </button>
            ))}
          </div>
        </section>

        <section className="card form-grid">
          <div className="card-head">
            <h3>{selectedTech ? `${selectedTech.technique_id} — ${selectedTech.technique_name}` : "Tests"}</h3>
            {selectedTech && <Link className="link" href={`/dashboards?technique=${encodeURIComponent(selectedTech.technique_id)}`}>Dashboard →</Link>}
          </div>
          <div className="usecase-list" style={{ maxHeight: 640 }}>
            {tests.map((t) => (
              <div key={t.id} className="selected-usecase">
                <div className="usecase-head">
                  <strong>{t.test_name}</strong>
                  <span className="badge">{t.executor}{t.elevation_required ? " · admin" : ""}</span>
                </div>
                <div className="muted small-text">{t.description}</div>
                <div className="badge-row" style={{ margin: "8px 0" }}>
                  {t.platforms.map((p) => <span key={p} className="badge soft">{p}</span>)}
                </div>
                {t.command && (
                  <div>
                    <div className="result-header">
                      <span className="muted small-text">command</span>
                      <button className="button secondary" type="button" onClick={() => copy(t.command, t.guid)}>{copiedGuid === t.guid ? "Copied" : "Copy"}</button>
                    </div>
                    <pre className="code query-output" style={{ maxHeight: 160 }}>{t.command}</pre>
                  </div>
                )}
              </div>
            ))}
            {tests.length === 0 && <div className="muted">No tests for this technique.</div>}
          </div>
        </section>
      </section>
    </div>
  );
}
