import { getSystemStatus, getReconCapabilities, getTargets, getStats, apiBase } from "../../lib/api";
import { FEATURES, AI_PROVIDER, AI_PROVIDER_LABEL, AI_ENABLED } from "../../lib/features";
import PageHeader from "../../components/PageHeader";
import SystemStatus from "../../components/SystemStatus";
import { IconSettings, IconSpark, IconCrosshair, IconCheck, IconWarn } from "../../components/icons";

export default async function SettingsPage() {
  const [status, recon, targets, stats] = await Promise.all([
    getSystemStatus(), getReconCapabilities(), getTargets(), getStats(),
  ]);
  const profiles = targets.reduce((s, t) => s + t.profiles.length, 0);

  return (
    <div className="grid">
      <PageHeader
        eyebrow="Platform"
        icon={<IconSettings />}
        title="Settings"
        sub="Workspace configuration, live platform status, and capability readiness. Editable organization profiles, field mappings, and access controls arrive in a later phase."
      />

      <SystemStatus status={status} variant="full" />

      {/* AI readiness */}
      <section className="cards two-column">
        <div className="card" style={{ display: "grid", gap: 12 }}>
          <div className="card-head" style={{ marginBottom: 0 }}>
            <h3 style={{ display: "flex", alignItems: "center", gap: 8 }}><IconSpark /> AI Assistance</h3>
            {AI_ENABLED
              ? <span className="status-pill ok">Active</span>
              : <span className="badge soft">Not configured</span>}
          </div>
          <div className="kv"><span className="k">Status</span><span className="v">{AI_ENABLED ? "Enabled" : "Disabled"}</span></div>
          <div className="kv"><span className="k">Provider</span><span className="v">{AI_PROVIDER_LABEL[AI_PROVIDER]}</span></div>
          <div className="kv"><span className="k">Local runtime</span><span className="v">{FEATURES.ai.localConfigured ? "Configured" : "Not configured"}</span></div>
          <div className="muted small-text" style={{ marginTop: 2 }}>
            The platform is fully functional without AI. Only free/local providers are supported — no paid cloud APIs and no fabricated output.
            Set <code>NEXT_PUBLIC_AI_PROVIDER</code> to <code>rule_based</code>, <code>local_ollama</code>, or <code>local_transformers</code> to enable.
          </div>
          <div>
            <div className="muted small-text" style={{ marginBottom: 6 }}>Planned AI features</div>
            <div className="badge-row">
              {FEATURES.ai.planned.map((f) => <span className="badge soft" key={f}>{f}</span>)}
            </div>
          </div>
        </div>

        {/* Automation readiness */}
        <div className="card" style={{ display: "grid", gap: 12 }}>
          <div className="card-head" style={{ marginBottom: 0 }}>
            <h3 style={{ display: "flex", alignItems: "center", gap: 8 }}><IconCrosshair /> Automation &amp; Recon</h3>
            {recon.renderingAvailable
              ? <span className="status-pill ok">Rendering available</span>
              : <span className="badge soft">HTTP-only</span>}
          </div>
          <div className="kv">
            <span className="k">Browser rendering (screenshots)</span>
            <span className="v">{recon.renderingAvailable ? "Available" : "Not installed"}</span>
          </div>
          <div className="kv"><span className="k">Recon scans run</span><span className="v">{recon.scans.toLocaleString()}</span></div>
          <div className="kv"><span className="k">Aggressive scanning</span><span className="v" style={{ display: "inline-flex", alignItems: "center", gap: 6 }}><IconCheck /> Disabled</span></div>
          <div className="kv"><span className="k">Scheduler</span><span className="v">{FEATURES.scheduler.enabled ? "Enabled" : "Manual (planned)"}</span></div>
          <div className="muted small-text" style={{ marginTop: 2 }}>
            Attack-surface assessment is passive and authorization-focused. Browser rendering is optional — when Selenium and a browser are present the engine captures a screenshot, otherwise it completes HTTP-only.
          </div>
        </div>
      </section>

      {/* Conversion catalog */}
      <section className="cards two-column">
        <div className="card">
          <h3>Workspace</h3>
          <div className="kv"><span className="k">API base URL</span><span className="v mono" style={{ fontSize: 12, wordBreak: "break-all" }}>{apiBase}</span></div>
          <div className="kv"><span className="k">Environment</span><span className="v">{status.env || "—"}</span></div>
          <div className="kv"><span className="k">Detections indexed</span><span className="v">{stats.rules.toLocaleString()}</span></div>
          <div className="kv"><span className="k">Configured sources</span><span className="v">{status.sourceCount}</span></div>
        </div>
        <div className="card">
          <h3>Conversion Catalog</h3>
          <div className="kv"><span className="k">SIEM targets</span><span className="v">{targets.length}</span></div>
          <div className="kv"><span className="k">Conversion profiles</span><span className="v">{profiles}</span></div>
          <div className="kv"><span className="k">ATT&CK tactics</span><span className="v">{stats.tactics}</span></div>
          <div className="kv"><span className="k">Report export</span><span className="v">{FEATURES.reports.exportPdf ? "Enabled" : "Planned"}</span></div>
        </div>
      </section>

      <div className="alert">
        <strong style={{ display: "flex", alignItems: "center", gap: 6 }}><IconWarn /> Planned settings</strong>
        <span>Organization conversion profiles, custom field mappings, saved use cases, source sync scheduler, authentication and roles, and approval workflows for generated queries.</span>
      </div>
    </div>
  );
}
