import Link from "next/link";
import {
  getHealth, getStats, getTactics, getUseCases, getRules, getTargets, getRepositories, getSystemStatus,
} from "../lib/api";
import PageHeader from "../components/PageHeader";
import SystemStatus from "../components/SystemStatus";
import {
  IconOverview, IconRules, IconLayers, IconShield, IconTerminal,
  IconBolt, IconDatabase, IconPulse,
} from "../components/icons";

const TACTIC_ORDER = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution",
  "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Discovery", "Lateral Movement", "Collection", "Command and Control",
  "Exfiltration", "Impact",
];

const SEV_ORDER = ["critical", "high", "medium", "low", "informational"];
const SEV_COLOR: Record<string, string> = {
  critical: "var(--crit)", high: "var(--high)", medium: "var(--med)",
  low: "var(--low)", informational: "var(--info)", unknown: "var(--info)",
};

export default async function DashboardPage() {
  const [health, stats, tactics, useCases, rules, targets, repos, status] = await Promise.all([
    getHealth(), getStats(), getTactics(), getUseCases(), getRules(), getTargets(), getRepositories(), getSystemStatus(),
  ]);

  const tacticMap = new Map(tactics.map((t) => [t.tactic, t.rule_count]));
  const maxTactic = Math.max(1, ...tactics.map((t) => t.rule_count));
  const topUseCases = [...useCases].sort((a, b) => b.rule_count - a.rule_count).slice(0, 10);

  // quality distribution (0-100)
  const qBuckets = [
    { label: "Strong", min: 75, color: "var(--emerald)", n: 0 },
    { label: "Good", min: 50, color: "var(--blue)", n: 0 },
    { label: "Fair", min: 30, color: "var(--high)", n: 0 },
    { label: "Weak", min: 0, color: "var(--crit)", n: 0 },
  ];
  for (const r of rules) {
    const b = qBuckets.find((x) => r.quality_score >= x.min);
    if (b) b.n++;
  }
  const qMax = Math.max(1, ...qBuckets.map((b) => b.n));

  // severity mix
  const sevCounts: Record<string, number> = {};
  for (const r of rules) {
    const s = (r.severity || "unknown").toLowerCase();
    sevCounts[s] = (sevCounts[s] || 0) + 1;
  }
  const sevMax = Math.max(1, ...Object.values(sevCounts));

  // source breakdown
  const sourceCounts: Record<string, number> = {};
  for (const r of rules) sourceCounts[r.source_repo] = (sourceCounts[r.source_repo] || 0) + 1;
  const topSources = Object.entries(sourceCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const srcMax = Math.max(1, ...topSources.map(([, n]) => n));

  const weakRules = rules.filter((r) => r.quality_score < 40 || r.mitre_techniques.length === 0).length;
  const apiOk = health?.status === "ok";

  return (
    <div className="grid">
      <PageHeader
        eyebrow="Command Center"
        icon={<IconOverview />}
        title="Security Operations Overview"
        sub="A unified view of your detection coverage — normalized rules, MITRE ATT&CK alignment, multi-SIEM readiness, and source health."
        actions={
          <>
            <Link className="button" href="/convert"><IconTerminal /> Generate Query</Link>
            <Link className="button secondary" href="/mitre"><IconShield /> MITRE Coverage</Link>
          </>
        }
      />

      <SystemStatus status={status} variant="compact" />

      {stats.rules === 0 && (
        <div className="alert">
          <strong>No detections imported yet.</strong>
          <span>Run <code>POST /api/repositories/sync</code> then <code>POST /api/rules/import</code> to populate the library. The portal renders live data as soon as the import completes.</span>
        </div>
      )}

      {/* KPI row */}
      <section className="cards four-cards">
        <div className="card stat-card">
          <div className="stat-top">
            <div className="stat-label">Detection Rules</div>
            <span className="stat-ico"><IconRules /></span>
          </div>
          <div className="kpi">{stats.rules.toLocaleString()}</div>
          <div className="muted">{weakRules} flagged for review</div>
        </div>
        <div className="card stat-card">
          <div className="stat-top">
            <div className="stat-label">Use Cases</div>
            <span className="stat-ico"><IconLayers /></span>
          </div>
          <div className="kpi">{useCases.length.toLocaleString()}</div>
          <div className="muted">MITRE-grouped detections</div>
        </div>
        <div className="card stat-card">
          <div className="stat-top">
            <div className="stat-label">ATT&CK Techniques</div>
            <span className="stat-ico"><IconShield /></span>
          </div>
          <div className="kpi">{stats.techniques.toLocaleString()}</div>
          <div className="muted">across {stats.tactics} tactics</div>
        </div>
        <div className="card stat-card">
          <div className="stat-top">
            <div className="stat-label">SIEM Targets</div>
            <span className="stat-ico"><IconTerminal /></span>
          </div>
          <div className="kpi">{targets.length.toLocaleString()}</div>
          <div className={`status-pill ${apiOk ? "ok" : "down"}`}>{apiOk ? "Platform online" : "API offline"}</div>
        </div>
      </section>

      {/* coverage + top use cases */}
      <section className="cards two-column">
        <div className="card">
          <div className="card-head">
            <h3>ATT&CK Tactic Coverage</h3>
            <Link className="link" href="/mitre">View matrix →</Link>
          </div>
          {stats.rules === 0 ? (
            <div className="muted small-text">Coverage appears here once detections are imported.</div>
          ) : (
            <div className="bars">
              {TACTIC_ORDER.map((tactic) => {
                const count = tacticMap.get(tactic) || 0;
                const pct = Math.round((count / maxTactic) * 100);
                return (
                  <Link className="bar-row" key={tactic} href={`/mitre?tactic=${encodeURIComponent(tactic)}`}>
                    <span className="bar-label">{tactic}</span>
                    <span className="bar-track"><span className="bar-fill" style={{ width: `${pct}%` }} /></span>
                    <span className="bar-value">{count.toLocaleString()}</span>
                  </Link>
                );
              })}
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-head">
            <h3>Top Use Cases</h3>
            <Link className="link" href="/use-cases">All use cases →</Link>
          </div>
          {topUseCases.length === 0 ? (
            <div className="muted small-text">No use cases yet.</div>
          ) : (
            <div className="usecase-list" style={{ maxHeight: 360 }}>
              {topUseCases.map((uc) => (
                <Link key={uc.id} className="usecase-item" href={`/use-cases?focus=${encodeURIComponent(uc.technique_id || uc.id)}`}>
                  <div className="usecase-head">
                    <strong>{uc.technique_id || uc.name}</strong>
                    <span className="count-chip">{uc.rule_count} detections</span>
                  </div>
                  <div className="muted small-text">{uc.tactics.join(", ") || "Unmapped"} · best quality {uc.best_quality_score}</div>
                </Link>
              ))}
            </div>
          )}
        </div>
      </section>

      {/* distributions */}
      <section className="cards three-column">
        <div className="card">
          <div className="card-head"><h3>Rule Quality</h3><span className="card-icon"><IconPulse /></span></div>
          <div className="bars">
            {qBuckets.map((b) => (
              <div className="bar-row" key={b.label}>
                <span className="bar-label">{b.label}</span>
                <span className="bar-track"><span className="bar-fill" style={{ width: `${Math.round((b.n / qMax) * 100)}%`, background: b.color, boxShadow: "none" }} /></span>
                <span className="bar-value">{b.n}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-head"><h3>Severity Mix</h3><span className="card-icon"><IconBolt /></span></div>
          <div className="bars">
            {SEV_ORDER.map((s) => (
              <div className="bar-row" key={s}>
                <span className="bar-label" style={{ textTransform: "capitalize" }}>{s}</span>
                <span className="bar-track"><span className="bar-fill" style={{ width: `${Math.round(((sevCounts[s] || 0) / sevMax) * 100)}%`, background: SEV_COLOR[s], boxShadow: "none" }} /></span>
                <span className="bar-value">{sevCounts[s] || 0}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-head"><h3>Coverage by Source</h3><span className="card-icon"><IconDatabase /></span></div>
          {topSources.length === 0 ? (
            <div className="muted small-text">No sources imported yet.</div>
          ) : (
            <div className="bars">
              {topSources.map(([name, n]) => (
                <div className="bar-row" key={name}>
                  <span className="bar-label" title={name}>{name}</span>
                  <span className="bar-track"><span className="bar-fill" style={{ width: `${Math.round((n / srcMax) * 100)}%` }} /></span>
                  <span className="bar-value">{n}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>

      {/* targets + sources */}
      <section className="cards two-column">
        <div className="card">
          <div className="card-head">
            <h3>Supported SIEM Targets</h3>
            <Link className="link" href="/convert">Open generator →</Link>
          </div>
          {targets.length === 0 ? (
            <div className="muted small-text">Target catalog unavailable.</div>
          ) : (
            <div className="target-grid">
              {targets.map((t) => (
                <div className="target-card" key={t.id}>
                  <strong>{t.name}</strong>
                  <span>{t.profiles.length} profiles · {t.formats.length} formats</span>
                  <span className="badge soft" style={{ width: "fit-content" }}>{t.support_level}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-head">
            <h3>Sources &amp; Sync Health</h3>
            <Link className="link" href="/sources">Manage sources →</Link>
          </div>
          {repos.length === 0 ? (
            <div className="muted small-text">No sources configured.</div>
          ) : (
            <div className="table-wrap">
              <table className="table compact-table">
                <thead><tr><th>Source</th><th>Type</th><th>Status</th></tr></thead>
                <tbody>
                  {repos.slice(0, 8).map((r) => {
                    const ok = r.last_sync_status === "success" || r.last_sync_status === "ok";
                    return (
                      <tr key={r.name}>
                        <td style={{ fontWeight: 600 }}>{r.name}</td>
                        <td><span className="badge soft">{r.type}</span></td>
                        <td>
                          <span className={`status-pill ${ok ? "ok" : "down"}`}>
                            {r.last_sync_status || (r.enabled ? "pending" : "disabled")}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
