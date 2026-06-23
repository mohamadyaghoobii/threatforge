"use client";

import { useEffect, useMemo, useState } from "react";
import { apiBase, Indicator, IntelStats, UserAgentRow } from "../../lib/api";
import PageHeader from "../../components/PageHeader";
import { IconRadar, IconRefresh, IconDownload } from "../../components/icons";

type Tab = "iocs" | "useragents";

function SevChip({ s }: { s: string }) {
  return <span className={`sev sev-${(s || "unknown").toLowerCase()}`}>{s || "—"}</span>;
}

export default function IntelPage() {
  const [stats, setStats] = useState<IntelStats | null>(null);
  const [tab, setTab] = useState<Tab>("iocs");
  const [iocType, setIocType] = useState("");
  const [severity, setSeverity] = useState("");
  const [q, setQ] = useState("");
  const [iocs, setIocs] = useState<Indicator[]>([]);
  const [uas, setUas] = useState<UserAgentRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [schedStatus, setSchedStatus] = useState<any>(null);
  const [sources, setSources] = useState<any[]>([]);
  const [lookupValue, setLookupValue] = useState("");
  const [lookupResult, setLookupResult] = useState<any>(null);

  async function loadStats() {
    const res = await fetch(`${apiBase}/api/intel/stats`, { cache: "no-store" });
    if (res.ok) setStats(await res.json());
    const st = await fetch(`${apiBase}/api/intel/status`, { cache: "no-store" });
    if (st.ok) setSchedStatus(await st.json());
    const sr = await fetch(`${apiBase}/api/intel/sources`, { cache: "no-store" });
    if (sr.ok) setSources(await sr.json());
  }

  async function doLookup() {
    if (!lookupValue.trim()) return;
    const res = await fetch(`${apiBase}/api/intel/lookup?value=${encodeURIComponent(lookupValue.trim())}`, { cache: "no-store" });
    setLookupResult(res.ok ? await res.json() : null);
  }

  async function loadData() {
    setLoading(true);
    const sevParam = severity ? `&severity=${severity}` : "";
    const qParam = q ? `&q=${encodeURIComponent(q)}` : "";
    if (tab === "iocs") {
      const typeParam = iocType ? `&type=${iocType}` : "";
      const res = await fetch(`${apiBase}/api/intel/iocs?limit=300${typeParam}${sevParam}${qParam}`, { cache: "no-store" });
      setIocs(res.ok ? await res.json() : []);
    } else {
      const res = await fetch(`${apiBase}/api/intel/useragents?limit=300${sevParam}${qParam}`, { cache: "no-store" });
      setUas(res.ok ? await res.json() : []);
    }
    setLoading(false);
  }

  useEffect(() => { loadStats(); }, []);
  useEffect(() => { loadData(); /* eslint-disable-next-line */ }, [tab, iocType, severity, q]);

  async function refresh() {
    setRefreshing(true);
    try {
      await fetch(`${apiBase}/api/intel/refresh`, { method: "POST" });
      await loadStats();
      await loadData();
    } finally {
      setRefreshing(false);
    }
  }

  const sevBuckets = useMemo(() => stats?.by_severity || {}, [stats]);

  return (
    <div className="grid">
      <PageHeader
        eyebrow="Threat Intelligence"
        icon={<IconRadar />}
        title="Threat Intelligence"
        sub="Unified, scored, de-duplicated indicators and malicious User-Agents aggregated from trusted open-source feeds — searchable, exportable, and SIEM-ready."
        actions={
          <>
            <button className="button" onClick={refresh} disabled={refreshing}><IconRefresh /> {refreshing ? "Refreshing…" : "Refresh feeds"}</button>
            <a className="button secondary" href={`${apiBase}/api/intel/${tab === "iocs" ? "iocs" : "useragents"}/export.csv`}><IconDownload /> Export CSV</a>
            <a className="button ghost" href={`${apiBase}/api/intel/iocs/export.stix`}>Export STIX 2.1</a>
          </>
        }
      />

      <section className="cards two-column">
        <div className="card">
          <div className="card-head"><h3>Auto-update</h3>
            <span className={`status-pill ${schedStatus?.enabled ? "ok" : "down"}`}>{schedStatus?.enabled ? "enabled" : "off"}</span>
          </div>
          {schedStatus?.enabled ? (
            <div className="muted">Refreshes every {schedStatus.interval_minutes} min · runs: {schedStatus.runs} · last: {schedStatus.last_run ? new Date(schedStatus.last_run).toLocaleString() : "—"}</div>
          ) : (
            <div className="muted">Background auto-update is off. Set INTEL_AUTO_REFRESH_MINUTES &gt; 0, or use Refresh feeds.</div>
          )}
          <div className="bars" style={{ marginTop: 12 }}>
            {sources.slice(0, 8).map((s, i) => (
              <div className="bar-row" key={i} style={{ gridTemplateColumns: "140px 1fr 90px" }}>
                <span className="bar-label">{s.source}</span>
                <span className="muted small-text">{s.kind} · {s.items} items</span>
                <span className={`status-pill ${s.status === "success" ? "ok" : "down"}`} style={{ marginTop: 0 }}>{s.status}</span>
              </div>
            ))}
            {sources.length === 0 && <div className="muted small-text">No runs yet — click Refresh feeds.</div>}
          </div>
        </div>

        <div className="card">
          <div className="card-head"><h3>IOC lookup</h3></div>
          <div className="muted" style={{ marginBottom: 10 }}>Check any IP, domain, URL, or hash against the library.</div>
          <div className="inline-fields" style={{ gridTemplateColumns: "1fr auto" }}>
            <input className="lookup-input" value={lookupValue} onChange={(e) => setLookupValue(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") doLookup(); }} placeholder="8.8.8.8 · evil.com · http://… · <sha256>" />
            <button className="button" onClick={doLookup}>Look up</button>
          </div>
          {lookupResult && (
            <div className={`alert ${lookupResult.known ? "error" : ""}`} style={{ marginTop: 12 }}>
              {lookupResult.known ? (
                <><strong>⚠ Known malicious</strong> — verdict <b>{lookupResult.verdict}</b>, max score {lookupResult.max_score}.
                  <div className="badge-row" style={{ marginTop: 8 }}>
                    {lookupResult.indicators.map((m: any, i: number) => (
                      <span key={i} className="badge">{m.ioc_type} · {m.severity} · {m.sources.join(",")}</span>
                    ))}
                  </div></>
              ) : (<><strong>✓ Not in library</strong> — no match for this value.</>)}
            </div>
          )}
        </div>
      </section>

      <section className="cards four-cards">
        <div className="card stat-card">
          <div className="stat-label">Indicators</div>
          <div className="kpi">{(stats?.indicators ?? 0).toLocaleString()}</div>
          <div className="muted">{stats?.indicators_active ?? 0} active</div>
        </div>
        <div className="card stat-card">
          <div className="stat-label">User-Agents</div>
          <div className="kpi">{(stats?.user_agents ?? 0).toLocaleString()}</div>
          <div className="muted">malicious / suspicious</div>
        </div>
        <div className="card stat-card">
          <div className="stat-label">Critical + High</div>
          <div className="kpi">{((sevBuckets.critical || 0) + (sevBuckets.high || 0)).toLocaleString()}</div>
          <div className="muted">high-priority IOCs</div>
        </div>
        <div className="card stat-card">
          <div className="stat-label">Sources</div>
          <div className="kpi">{Object.keys(stats?.by_source || {}).length}</div>
          <div className="muted">feeds merged</div>
        </div>
      </section>

      <section className="card">
        <div className="card-head">
          <div className="badge-row">
            <button className={`button ${tab === "iocs" ? "" : "secondary"}`} onClick={() => setTab("iocs")}>Indicators (IOCs)</button>
            <button className={`button ${tab === "useragents" ? "" : "secondary"}`} onClick={() => setTab("useragents")}>User-Agents</button>
          </div>
          <span className="muted">{tab === "iocs" ? iocs.length : uas.length} shown</span>
        </div>

        <div className="filter-grid" style={{ marginBottom: 14 }}>
          <label className="field span-2"><span>Search</span>
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={tab === "iocs" ? "domain, url, ip, tag..." : "user-agent, tool..."} />
          </label>
          {tab === "iocs" && (
            <label className="field"><span>Type</span>
              <select value={iocType} onChange={(e) => setIocType(e.target.value)}>
                <option value="">All types</option>
                <option value="url">URL</option>
                <option value="domain">Domain</option>
                <option value="ip">IP</option>
                <option value="hash">Hash</option>
              </select>
            </label>
          )}
          <label className="field"><span>Severity</span>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </label>
        </div>

        {loading && <div className="alert">Loading…</div>}

        {!loading && tab === "iocs" && (
          <table className="table">
            <thead><tr><th>Indicator</th><th>Type</th><th>Severity</th><th>Score</th><th>Category</th><th>Tags</th></tr></thead>
            <tbody>
              {iocs.map((r) => (
                <tr key={r.id}>
                  <td style={{ maxWidth: 480, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={r.ioc}>{r.ioc}</td>
                  <td><span className="badge soft">{r.ioc_type}</span></td>
                  <td><SevChip s={r.severity} /></td>
                  <td><strong>{r.threat_score}</strong></td>
                  <td>{r.category}</td>
                  <td><div className="badge-row">{r.tags.slice(0, 3).map((t, i) => <span key={i} className="badge">{t}</span>)}</div></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {!loading && tab === "useragents" && (
          <table className="table">
            <thead><tr><th>User-Agent</th><th>Tool</th><th>Severity</th><th>Category</th><th>Sources</th></tr></thead>
            <tbody>
              {uas.map((r) => (
                <tr key={r.id}>
                  <td style={{ maxWidth: 560, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={r.user_agent}><code>{r.user_agent}</code></td>
                  <td><span className="badge">{r.tool_name}</span></td>
                  <td><SevChip s={r.severity} /></td>
                  <td>{r.category}</td>
                  <td className="muted small-text">{r.sources.length}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
