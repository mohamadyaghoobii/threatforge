"use client";

import { FormEvent, useEffect, useState } from "react";
import { apiBase } from "../../lib/api";
import PageHeader from "../../components/PageHeader";
import { IconGlobe } from "../../components/icons";

type Finding = { severity: string; title: string; detail: string };
type Report = {
  id?: number; status: string; target: string; host: string; final_url: string;
  http_status: number | null; https: boolean; server: string | null; title: string;
  score: number; grade: string; findings: Finding[];
  security_headers: { present: any[]; missing: any[]; leaks: any[] };
  cookies: { name: string; secure: boolean; httponly: boolean; samesite: string | null; session_like: boolean }[];
  technologies: string[]; cms: string[]; cdn: string[];
  graphql: { detected: boolean; markers: string[] };
  secrets: { type: string; match: string; confidence: string; source?: string }[];
  assets: { internal_links?: string[]; external_links?: string[]; forms?: any[]; emails?: string[]; scripts?: string[] };
  subdomains: string[]; ips: string[]; dns: Record<string, string[]>;
  robots: { robots: boolean; sitemaps: string[]; disallow: string[] };
  exposed_paths: { path: string; severity: string; detail: string }[];
  js_intel: { files_analyzed: number; endpoints: string[]; secrets: any[] };
  wayback: string[]; urlscan: any[]; enrichment: Record<string, any>;
  rendered: boolean; render_error?: string | null; elapsed_ms: number;
};

const GRADE_COLOR: Record<string, string> = { A: "var(--low)", B: "var(--low)", C: "var(--med)", D: "var(--high)", F: "var(--crit)" };

export default function ReconPage() {
  const [stats, setStats] = useState<any>(null);
  const [target, setTarget] = useState("");
  const [render, setRender] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [recent, setRecent] = useState<any[]>([]);

  async function loadAux() {
    const s = await fetch(`${apiBase}/api/recon/stats`, { cache: "no-store" });
    if (s.ok) setStats(await s.json());
    const r = await fetch(`${apiBase}/api/recon/scans?limit=12`, { cache: "no-store" });
    if (r.ok) setRecent(await r.json());
  }
  useEffect(() => { loadAux(); }, []);

  async function scan(e: FormEvent) {
    e.preventDefault();
    if (!target.trim()) return;
    setBusy(true); setError(null); setReport(null);
    try {
      const res = await fetch(`${apiBase}/api/recon/scan`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim(), render, subdomains: true }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : `HTTP ${res.status}`);
      setReport(data);
      loadAux();
    } catch (e2) {
      setError(e2 instanceof Error ? e2.message : "scan failed");
    } finally {
      setBusy(false);
    }
  }

  const sh = report?.security_headers;

  return (
    <div className="grid">
      <PageHeader
        eyebrow="Attack Surface"
        icon={<IconGlobe />}
        title="Attack Surface Intelligence"
        sub="Passive external assessment of a domain or URL — DNS and subdomain inventory, TLS and security-header posture, technology fingerprint, exposed paths, and an optional rendered capture. Read-only reconnaissance using public sources; intended for assets you are authorized to assess."
      />

      <section className="card">
        <form className="form-grid" onSubmit={scan}>
          <div className="inline-fields" style={{ gridTemplateColumns: "1fr auto auto" }}>
            <input className="lookup-input" value={target} onChange={(e) => setTarget(e.target.value)}
              placeholder="example.com  ·  https://target.tld/path" />
            <label className="field" style={{ flexDirection: "row", alignItems: "center", gap: 8 }}>
              <input type="checkbox" checked={render} onChange={(e) => setRender(e.target.checked)} style={{ width: 16 }} />
              <span style={{ whiteSpace: "nowrap" }}>Render (screenshot)</span>
            </label>
            <button className="button" type="submit" disabled={busy}>{busy ? "Scanning…" : "Run recon"}</button>
          </div>
          {stats && (
            <div className="muted small-text">
              {stats.scans} scans · avg score {stats.avg_score} · browser rendering {stats.selenium_available ? "available" : "unavailable (HTTP-only)"}
            </div>
          )}
          {error && <div className="alert error">{error}</div>}
        </form>
      </section>

      {report && (
        <>
          <section className="cards four-cards">
            <div className="card stat-card">
              <div className="stat-label">Posture</div>
              <div className="kpi" style={{ color: GRADE_COLOR[report.grade] }}>{report.grade} · {report.score}</div>
              <div className="muted">{report.https ? "HTTPS" : "HTTP only"} · {report.http_status ?? "—"}</div>
            </div>
            <div className="card stat-card"><div className="stat-label">Technologies</div><div className="kpi">{report.technologies.length}</div><div className="muted">{report.cms.concat(report.cdn).slice(0, 3).join(", ") || "—"}</div></div>
            <div className="card stat-card"><div className="stat-label">Secrets</div><div className="kpi" style={{ color: report.secrets.length ? "var(--crit)" : undefined }}>{report.secrets.length}</div><div className="muted">exposed in source</div></div>
            <div className="card stat-card"><div className="stat-label">Subdomains</div><div className="kpi">{report.subdomains.length}</div><div className="muted">via crt.sh</div></div>
          </section>

          <section className="cards two-column">
            <div className="card">
              <div className="card-head"><h3>{report.title || report.host}</h3><span className="muted small-text">{report.elapsed_ms} ms</span></div>
              <div className="badge-row" style={{ marginBottom: 10 }}>
                {report.server && <span className="badge soft">server: {report.server}</span>}
                {report.ips.slice(0, 3).map((ip) => <span key={ip} className="badge soft">{ip}</span>)}
                {report.technologies.map((t) => <span key={t} className="badge">{t}</span>)}
                {report.cms.map((c) => <span key={c} className="badge">CMS: {c}</span>)}
                {report.cdn.map((c) => <span key={c} className="badge">CDN: {c}</span>)}
              </div>
              <h4 style={{ margin: "10px 0 6px" }}>Findings</h4>
              <div className="usecase-list" style={{ maxHeight: 260 }}>
                {report.findings.map((f, i) => (
                  <div key={i} className="usecase-item">
                    <div className="usecase-head"><strong>{f.title}</strong><span className={`sev sev-${f.severity}`}>{f.severity}</span></div>
                    <div className="muted small-text">{f.detail}</div>
                  </div>
                ))}
                {report.findings.length === 0 && <div className="muted small-text">No posture issues detected.</div>}
              </div>
            </div>

            <div className="card">
              <div className="card-head"><h3>Security headers</h3><span className="muted small-text">{sh?.present.length}/{(sh?.present.length || 0) + (sh?.missing.length || 0)} present</span></div>
              <div className="badge-row">
                {sh?.present.map((h: any) => <span key={h.header} className="badge" style={{ color: "var(--low)" }}>✓ {h.header}</span>)}
                {sh?.missing.map((h: any) => <span key={h.header} className="badge soft">✗ {h.header}</span>)}
              </div>
              {!!sh?.leaks.length && <div className="alert" style={{ marginTop: 12 }}><strong>Info leaks</strong><ul>{sh.leaks.map((l: any, i: number) => <li key={i}><code>{l.header}</code>: {l.value}</li>)}</ul></div>}
              {!!report.secrets.length && (
                <div className="alert error" style={{ marginTop: 12 }}>
                  <strong>Exposed secrets</strong>
                  <ul>{report.secrets.map((s, i) => <li key={i}><b>{s.type}</b>: <code>{s.match}</code></li>)}</ul>
                </div>
              )}
            </div>
          </section>

          {report.rendered && report.id && (
            <section className="card">
              <h3>Rendered screenshot</h3>
              <img src={`${apiBase}/api/recon/scans/${report.id}/screenshot.png`} alt="screenshot"
                style={{ maxWidth: "100%", borderRadius: 12, border: "1px solid var(--border)" }} />
            </section>
          )}
          {!report.rendered && render && (
            <section className="card"><div className="alert">Browser rendering unavailable on this host — HTTP recon completed without a screenshot.{report.render_error ? ` (${report.render_error})` : ""}</div></section>
          )}

          {!!report.exposed_paths?.length && (
            <section className="card">
              <div className="card-head"><h3>Exposed paths</h3><span className="muted small-text">{report.exposed_paths.length}</span></div>
              <table className="table">
                <thead><tr><th>Path</th><th>Severity</th><th>Detail</th></tr></thead>
                <tbody>
                  {report.exposed_paths.map((p, i) => (
                    <tr key={i}><td><code>{p.path}</code></td><td><span className={`sev sev-${p.severity}`}>{p.severity}</span></td><td className="muted small-text">{p.detail}</td></tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}

          <section className="cards two-column">
            {!!report.cookies?.length && (
              <div className="card">
                <div className="card-head"><h3>Cookies</h3><span className="muted small-text">{report.cookies.length}</span></div>
                <table className="table">
                  <thead><tr><th>Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th></tr></thead>
                  <tbody>
                    {report.cookies.map((c, i) => (
                      <tr key={i}>
                        <td>{c.name}{c.session_like ? " 🔑" : ""}</td>
                        <td>{c.secure ? "✓" : <span style={{ color: "var(--high)" }}>✗</span>}</td>
                        <td>{c.httponly ? "✓" : <span style={{ color: "var(--high)" }}>✗</span>}</td>
                        <td className="muted small-text">{c.samesite || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {report.dns && Object.keys(report.dns).length > 0 && (
              <div className="card">
                <div className="card-head"><h3>DNS records</h3></div>
                {Object.entries(report.dns).map(([t, vals]) => (
                  <div key={t} style={{ marginBottom: 6 }}>
                    <span className="badge">{t}</span>{" "}
                    <span className="muted small-text">{vals.slice(0, 6).join(", ")}</span>
                  </div>
                ))}
              </div>
            )}
          </section>

          {(report.js_intel?.endpoints?.length > 0 || report.js_intel?.secrets?.length > 0) && (
            <section className="card">
              <div className="card-head"><h3>JavaScript intel</h3><span className="muted small-text">{report.js_intel.files_analyzed} files analyzed</span></div>
              {!!report.js_intel.secrets.length && (
                <div className="alert error" style={{ marginBottom: 10 }}>
                  <strong>Secrets in JS</strong>
                  <ul>{report.js_intel.secrets.map((s: any, i: number) => <li key={i}><b>{s.type}</b>: <code>{s.match}</code></li>)}</ul>
                </div>
              )}
              <div className="badge-row">{report.js_intel.endpoints.slice(0, 60).map((e, i) => <span key={i} className="badge soft">{e}</span>)}</div>
            </section>
          )}

          <section className="cards two-column">
            {!!report.subdomains.length && (
              <div className="card">
                <div className="card-head"><h3>Subdomains</h3><span className="muted small-text">{report.subdomains.length} · crt.sh</span></div>
                <div className="badge-row" style={{ maxHeight: 220, overflow: "auto" }}>{report.subdomains.slice(0, 150).map((s) => <span key={s} className="badge soft">{s}</span>)}</div>
              </div>
            )}
            {!!report.wayback?.length && (
              <div className="card">
                <div className="card-head"><h3>Wayback URLs</h3><span className="muted small-text">{report.wayback.length}</span></div>
                <div className="usecase-list" style={{ maxHeight: 220 }}>{report.wayback.slice(0, 60).map((u, i) => <div key={i} className="muted small-text" style={{ wordBreak: "break-all" }}>{u}</div>)}</div>
              </div>
            )}
          </section>

          {report.enrichment && Object.keys(report.enrichment).length > 0 && (
            <section className="card">
              <h3>Enrichment (API-key sources)</h3>
              <pre className="code query-output" style={{ maxHeight: 300 }}>{JSON.stringify(report.enrichment, null, 2)}</pre>
            </section>
          )}

          {!!report.urlscan?.length && (
            <section className="card">
              <div className="card-head"><h3>urlscan.io history</h3><span className="muted small-text">{report.urlscan.length}</span></div>
              <table className="table">
                <thead><tr><th>URL</th><th>IP</th><th>Server</th><th>Country</th></tr></thead>
                <tbody>
                  {report.urlscan.slice(0, 15).map((u: any, i: number) => (
                    <tr key={i}><td className="muted small-text" style={{ maxWidth: 360, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{u.url}</td><td>{u.ip}</td><td>{u.server}</td><td>{u.country}</td></tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}
        </>
      )}

      {!report && recent.length > 0 && (
        <section className="card">
          <div className="card-head"><h3>Recent scans</h3></div>
          <table className="table">
            <thead><tr><th>Target</th><th>Grade</th><th>Score</th><th>Tech</th><th>Subdomains</th><th>Status</th></tr></thead>
            <tbody>
              {recent.map((r) => (
                <tr key={r.id}>
                  <td>{r.target}</td>
                  <td><span className={`sev sev-${r.grade === "A" || r.grade === "B" ? "low" : r.grade === "C" ? "medium" : r.grade === "D" ? "high" : "critical"}`}>{r.grade}</span></td>
                  <td><strong>{r.score}</strong></td>
                  <td className="muted small-text">{(r.technologies || []).slice(0, 3).join(", ")}</td>
                  <td>{r.subdomains_count}</td>
                  <td className="muted small-text">{r.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}
