import type { SystemStatus } from "../lib/api";
import { IconPulse, IconDatabase, IconRules, IconGlobe, IconDashboard, IconRefresh } from "./icons";

const MODE_META: Record<SystemStatus["mode"], { label: string; cls: string; note: string }> = {
  live: { label: "Live", cls: "ok", note: "Serving real-time data from the platform API." },
  degraded: { label: "Degraded", cls: "down", note: "API reachable, but data is empty or a source sync failed." },
  offline: { label: "Offline", cls: "down", note: "Platform API unreachable — showing safe empty states." },
};

function dotClass(mode: SystemStatus["mode"]) {
  return mode === "live" ? "" : mode === "degraded" ? "idle" : "down";
}

export default function SystemStatus({ status, variant = "compact" }: { status: SystemStatus; variant?: "compact" | "full" }) {
  const meta = MODE_META[status.mode];

  if (variant === "compact") {
    return (
      <div className="card" style={{ display: "grid", gap: 14 }}>
        <div className="card-head" style={{ marginBottom: 0 }}>
          <h3 style={{ display: "flex", alignItems: "center", gap: 9 }}>
            <span className={`status-dot ${dotClass(status.mode)}`} /> Live System Status
          </h3>
          <span className={`status-pill ${meta.cls}`}>{meta.label}</span>
        </div>
        <div className="status-strip">
          <div className="status-item"><span className="status-ico"><IconPulse /></span><div><div className="si-k">API</div><div className="si-v">{status.apiOnline ? "Online" : "Offline"}</div></div></div>
          <div className="status-item"><span className="status-ico"><IconDatabase /></span><div><div className="si-k">Database</div><div className="si-v">{status.dbConnected ? "Connected" : "Unavailable"}</div></div></div>
          <div className="status-item"><span className="status-ico"><IconRules /></span><div><div className="si-k">Detections</div><div className="si-v">{status.ruleCount.toLocaleString()}</div></div></div>
          <div className="status-item"><span className="status-ico"><IconRefresh /></span><div><div className="si-k">Sources synced</div><div className="si-v">{status.sourcesOk}/{status.sourceCount}</div></div></div>
          <div className="status-item"><span className="status-ico"><IconGlobe /></span><div><div className="si-k">Latest recon</div><div className="si-v">{status.latestRecon ? `${status.latestRecon.target}` : "—"}</div></div></div>
          <div className="status-item"><span className="status-ico"><IconDashboard /></span><div><div className="si-k">Latest dashboard</div><div className="si-v">{status.latestDashboard ? status.latestDashboard.target : "—"}</div></div></div>
        </div>
      </div>
    );
  }

  return (
    <section className="card" style={{ display: "grid", gap: 16 }}>
      <div className="card-head" style={{ marginBottom: 0 }}>
        <h3 style={{ display: "flex", alignItems: "center", gap: 9 }}>
          <span className={`status-dot ${dotClass(status.mode)}`} /> Live System Status
        </h3>
        <span className={`status-pill ${meta.cls}`}>Mode: {meta.label}</span>
      </div>
      <div className="muted small-text" style={{ marginTop: -6 }}>{meta.note}</div>

      <div className="cards four-cards" style={{ gap: 12 }}>
        <div className="mini-stat"><div className="si-k">API</div><div className="si-v">{status.apiOnline ? "Online" : "Offline"}</div></div>
        <div className="mini-stat"><div className="si-k">Database</div><div className="si-v">{status.dbConnected ? "Connected" : "Unavailable"}</div></div>
        <div className="mini-stat"><div className="si-k">Environment</div><div className="si-v">{status.env || "—"}</div></div>
        <div className="mini-stat"><div className="si-k">Detections</div><div className="si-v">{status.ruleCount.toLocaleString()}</div></div>
      </div>

      <div className="divider" />

      <div className="cards three-column" style={{ gap: 12 }}>
        <div className="kv"><span className="k">Sources synced</span><span className="v">{status.sourcesOk}/{status.sourceCount}{status.sourcesFailed ? ` · ${status.sourcesFailed} failed` : ""}</span></div>
        <div className="kv"><span className="k">Last import</span><span className="v">{status.lastImport || "Not tracked yet"}</span></div>
        <div className="kv"><span className="k">Next scheduled sync</span><span className="v">{status.nextSync || "Manual (scheduler planned)"}</span></div>
        <div className="kv"><span className="k">Latest recon scan</span><span className="v">{status.latestRecon ? `${status.latestRecon.target} · ${status.latestRecon.grade ?? "—"}` : "None yet"}</span></div>
        <div className="kv"><span className="k">Latest dashboard</span><span className="v">{status.latestDashboard ? `${status.latestDashboard.name}` : "None yet"}</span></div>
        <div className="kv"><span className="k">Data mode</span><span className="v" style={{ textTransform: "capitalize" }}>{status.mode}</span></div>
      </div>

      {status.sources.length > 0 && (
        <>
          <div className="divider" />
          <div>
            <div className="muted small-text" style={{ marginBottom: 8 }}>Source sync status</div>
            <div className="table-wrap">
              <table className="table compact-table">
                <thead><tr><th>Source</th><th>Type</th><th>Last commit</th><th>Status</th></tr></thead>
                <tbody>
                  {status.sources.map((s) => {
                    const ok = s.status === "success" || s.status === "ok";
                    return (
                      <tr key={s.name}>
                        <td style={{ fontWeight: 600 }}>{s.name}</td>
                        <td><span className="badge soft">{s.type}</span></td>
                        <td className="mono" style={{ fontSize: 12 }}>{s.lastCommit ? s.lastCommit.slice(0, 10) : "—"}</td>
                        <td><span className={`status-pill ${ok ? "ok" : "down"}`}>{s.status}</span></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </section>
  );
}
