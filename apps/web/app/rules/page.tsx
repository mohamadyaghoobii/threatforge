import { getFilterOptions, getRules, getStats } from "../../lib/api";
import PageHeader from "../../components/PageHeader";
import RulesExplorer from "../../components/RulesExplorer";
import { IconRules } from "../../components/icons";

export default async function RulesPage({
  searchParams,
}: {
  searchParams: Promise<{ q?: string }>;
}) {
  const { q } = await searchParams;
  const [rules, filters, stats] = await Promise.all([getRules(), getFilterOptions(), getStats()]);

  return (
    <div className="grid">
      <PageHeader
        eyebrow="Detection Engineering"
        icon={<IconRules />}
        title="Detection Rule Explorer"
        sub="Browse, filter, and assess the normalized detection corpus. Quality scores and review flags surface weak or incomplete rules; open any detection for the full definition and conversion."
      />

      <section className="cards four-cards">
        <div className="card stat-card">
          <div className="stat-label">Detections</div>
          <div className="kpi">{stats.rules.toLocaleString()}</div>
          <div className="muted">normalized rules</div>
        </div>
        <div className="card stat-card">
          <div className="stat-label">Products</div>
          <div className="kpi">{filters.products.length}</div>
          <div className="muted">telemetry products</div>
        </div>
        <div className="card stat-card">
          <div className="stat-label">Categories</div>
          <div className="kpi">{filters.categories.length}</div>
          <div className="muted">detection categories</div>
        </div>
        <div className="card stat-card">
          <div className="stat-label">Sources</div>
          <div className="kpi">{filters.sources.length}</div>
          <div className="muted">rule libraries</div>
        </div>
      </section>

      <RulesExplorer rules={rules} filters={filters} total={stats.rules} initialQuery={q || ""} />
    </div>
  );
}
