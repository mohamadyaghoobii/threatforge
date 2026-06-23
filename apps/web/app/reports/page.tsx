import Link from "next/link";
import { getStats, getTactics, getUseCases, getRules, getTargets } from "../../lib/api";
import PageHeader from "../../components/PageHeader";
import { IconReport, IconDownload, IconShield, IconWarn } from "../../components/icons";

const TACTIC_ORDER = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution",
  "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Discovery", "Lateral Movement", "Collection", "Command and Control",
  "Exfiltration", "Impact",
];

export default async function ReportsPage() {
  const [stats, tactics, useCases, rules, targets] = await Promise.all([
    getStats(), getTactics(), getUseCases(), getRules(), getTargets(),
  ]);

  const tacticMap = new Map(tactics.map((t) => [t.tactic, t.rule_count]));
  const coveredTactics = TACTIC_ORDER.filter((t) => (tacticMap.get(t) || 0) > 0);
  const gapTactics = TACTIC_ORDER.filter((t) => (tacticMap.get(t) || 0) === 0);
  const thin = TACTIC_ORDER
    .map((t) => ({ t, n: tacticMap.get(t) || 0 }))
    .filter((x) => x.n > 0)
    .sort((a, b) => a.n - b.n)
    .slice(0, 4);

  const weak = rules.filter((r) => r.quality_score < 40 || r.mitre_techniques.length === 0).length;
  const avgQuality = rules.length ? Math.round(rules.reduce((s, r) => s + r.quality_score, 0) / rules.length) : 0;
  const critHigh = rules.filter((r) => ["critical", "high"].includes((r.severity || "").toLowerCase())).length;
  const coveragePct = Math.round((coveredTactics.length / TACTIC_ORDER.length) * 100);

  return (
    <div className="grid">
      <PageHeader
        eyebrow="Reporting"
        icon={<IconReport />}
        title="Security Reports"
        sub="A live executive snapshot of detection posture across the ATT&CK kill chain. Formatted export to PDF, Markdown, and JSON is planned for a later phase."
        actions={
          <>
            <button className="button secondary" disabled title="Planned for a later phase"><IconDownload /> Export PDF</button>
            <button className="button ghost" disabled title="Planned for a later phase"><IconDownload /> Markdown</button>
          </>
        }
      />

      {/* Executive summary */}
      <section className="card">
        <div className="card-head"><h3>Executive Summary</h3><span className="badge soft">live snapshot</span></div>
        <p className="muted" style={{ marginTop: 0, lineHeight: 1.7 }}>
          The detection program currently maintains <strong style={{ color: "var(--text)" }}>{stats.rules.toLocaleString()}</strong> normalized
          detections grouped into <strong style={{ color: "var(--text)" }}>{useCases.length.toLocaleString()}</strong> ATT&CK use cases,
          covering <strong style={{ color: "var(--text)" }}>{coveredTactics.length} of {TACTIC_ORDER.length}</strong> tactics
          ({coveragePct}% of the kill chain) and <strong style={{ color: "var(--text)" }}>{stats.techniques.toLocaleString()}</strong> techniques.
          Detections are convertible to <strong style={{ color: "var(--text)" }}>{targets.length}</strong> SIEM targets.
          Average rule quality is <strong style={{ color: "var(--text)" }}>{avgQuality}/100</strong>, with <strong style={{ color: "var(--text)" }}>{weak}</strong> detections
          flagged for review.
        </p>
      </section>

      <section className="cards four-cards">
        <div className="card stat-card"><div className="stat-label">Kill-chain Coverage</div><div className="kpi">{coveragePct}%</div><div className="muted">{coveredTactics.length}/{TACTIC_ORDER.length} tactics</div></div>
        <div className="card stat-card"><div className="stat-label">Avg Rule Quality</div><div className="kpi">{avgQuality}</div><div className="muted">of 100</div></div>
        <div className="card stat-card"><div className="stat-label">Critical + High</div><div className="kpi">{critHigh.toLocaleString()}</div><div className="muted">high-priority detections</div></div>
        <div className="card stat-card"><div className="stat-label">Flagged for Review</div><div className="kpi">{weak.toLocaleString()}</div><div className="muted">weak or unmapped</div></div>
      </section>

      <section className="cards two-column">
        <div className="card">
          <div className="card-head"><h3 style={{ display: "flex", alignItems: "center", gap: 8 }}><IconWarn /> Detection Gaps</h3></div>
          {gapTactics.length === 0 && thin.length === 0 ? (
            <div className="muted small-text">No obvious tactic-level gaps in the current corpus.</div>
          ) : (
            <>
              {gapTactics.length > 0 && (
                <div style={{ marginBottom: 14 }}>
                  <div className="muted small-text" style={{ marginBottom: 8 }}>No coverage</div>
                  <div className="badge-row">{gapTactics.map((t) => <span className="sev sev-high" key={t}>{t}</span>)}</div>
                </div>
              )}
              {thin.length > 0 && (
                <div>
                  <div className="muted small-text" style={{ marginBottom: 8 }}>Thin coverage</div>
                  <div className="bars">
                    {thin.map(({ t, n }) => (
                      <div className="bar-row" key={t} style={{ gridTemplateColumns: "150px 1fr 52px" }}>
                        <span className="bar-label">{t}</span>
                        <span className="bar-track"><span className="bar-fill" style={{ width: `${Math.min(100, n * 8)}%`, background: "var(--high)", boxShadow: "none" }} /></span>
                        <span className="bar-value">{n}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        <div className="card">
          <div className="card-head"><h3 style={{ display: "flex", alignItems: "center", gap: 8 }}><IconShield /> SIEM Readiness</h3><Link className="link" href="/convert">Generator →</Link></div>
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
      </section>

      <div className="alert">
        <strong>Coming in a later phase</strong>
        <span>Scheduled report generation, remediation prioritization, and export to PDF / Markdown / JSON with an executive + technical split.</span>
      </div>
    </div>
  );
}
