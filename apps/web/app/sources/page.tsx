import { getRepositories, getStats } from "../../lib/api";
import PageHeader from "../../components/PageHeader";
import { IconDatabase } from "../../components/icons";

export default async function SourcesPage() {
  const [repos, stats] = await Promise.all([getRepositories(), getStats()]);

  const enabled = repos.filter((r) => r.enabled).length;
  const synced = repos.filter((r) => r.last_sync_status === "success" || r.last_sync_status === "ok").length;

  return (
    <div className="grid">
      <PageHeader
        eyebrow="Platform"
        icon={<IconDatabase />}
        title="Detection Sources"
        sub="Rule libraries feeding the detection corpus. External repositories are imported read-only, hashed for de-duplication, then normalized and scored."
      />

      <section className="cards four-cards">
        <div className="card stat-card"><div className="stat-label">Configured</div><div className="kpi">{repos.length}</div><div className="muted">rule libraries</div></div>
        <div className="card stat-card"><div className="stat-label">Enabled</div><div className="kpi">{enabled}</div><div className="muted">active for import</div></div>
        <div className="card stat-card"><div className="stat-label">Synced</div><div className="kpi">{synced}</div><div className="muted">last sync ok</div></div>
        <div className="card stat-card"><div className="stat-label">Detections</div><div className="kpi">{stats.rules.toLocaleString()}</div><div className="muted">normalized rules</div></div>
      </section>

      {repos.length === 0 ? (
        <div className="card"><div className="empty">
          <div className="empty-icon"><IconDatabase /></div>
          <h3>No sources configured</h3>
          <p>Sources are defined in <code>configs/sources/repositories.yml</code>. The API exposes them at <code>GET /api/repositories</code>.</p>
        </div></div>
      ) : (
        <section className="card">
          <div className="card-head"><h3>Repositories</h3></div>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr><th>Source</th><th>Type</th><th>Branch</th><th>License</th><th>Last commit</th><th>Status</th></tr>
              </thead>
              <tbody>
                {repos.map((r) => {
                  const ok = r.last_sync_status === "success" || r.last_sync_status === "ok";
                  return (
                    <tr key={r.name}>
                      <td>
                        <div style={{ fontWeight: 600 }}>{r.name}</div>
                        <div className="faint" style={{ fontSize: 11.5, marginTop: 2, wordBreak: "break-all" }}>{r.url}</div>
                      </td>
                      <td><span className="badge soft">{r.type}</span></td>
                      <td className="mono" style={{ fontSize: 12 }}>{r.branch}</td>
                      <td className="muted small-text">{r.license || "—"}</td>
                      <td className="mono" style={{ fontSize: 12 }}>{r.last_commit_hash ? r.last_commit_hash.slice(0, 10) : "—"}</td>
                      <td>
                        {!r.enabled
                          ? <span className="status-pill down">disabled</span>
                          : <span className={`status-pill ${ok ? "ok" : "down"}`}>{r.last_sync_status || "pending"}</span>}
                        {r.last_sync_error && <div className="flag" style={{ marginTop: 4 }}>{r.last_sync_error.slice(0, 60)}</div>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <div className="alert">
        <strong>Syncing &amp; importing</strong>
        <span>Source sync and rule import are operational API actions: <code>POST /api/repositories/sync</code> then <code>POST /api/rules/import</code>. Scheduled, in-app sync controls are planned for a later phase.</span>
      </div>
    </div>
  );
}
