import Link from "next/link";
import PageHeader from "../../../components/PageHeader";
import RuleCode from "../../../components/RuleCode";
import { IconRules, IconTerminal, IconArrow } from "../../../components/icons";

const apiBase = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

function qualityColor(score: number) {
  if (score >= 75) return "var(--emerald)";
  if (score >= 50) return "var(--blue)";
  if (score >= 30) return "var(--high)";
  return "var(--crit)";
}

async function getRule(id: string) {
  try {
    const res = await fetch(`${apiBase}/api/rules/${id}`, { cache: "no-store" });
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export default async function RuleDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const rule = await getRule(id);

  if (!rule) {
    return (
      <div className="grid">
        <PageHeader eyebrow="Detection Engineering" icon={<IconRules />} title="Detection not found" sub="This detection may have been re-imported with a new id." />
        <div className="card">
          <div className="empty">
            <h3>We couldn’t load this detection</h3>
            <p>Return to the explorer to find it again.</p>
            <Link className="button secondary" href="/rules"><IconArrow /> Back to Detection Rules</Link>
          </div>
        </div>
      </div>
    );
  }

  const sev = (rule.severity || "unknown").toLowerCase();
  const q = rule.quality_score ?? 0;

  return (
    <div className="grid">
      <PageHeader
        eyebrow="Detection Detail"
        icon={<IconRules />}
        title={rule.title}
        sub={rule.description || "No description provided for this detection."}
        actions={
          <>
            <Link className="button" href={`/convert?rule=${rule.id}`}><IconTerminal /> Convert to SIEM</Link>
            <Link className="button ghost" href="/rules"><IconArrow /> Back</Link>
          </>
        }
      />

      <section className="cards two-column">
        <div className="card">
          <h3>Classification</h3>
          <div className="badge-row" style={{ marginBottom: 14 }}>
            <span className={`sev sev-${sev}`}>{sev}</span>
            {rule.status && <span className="badge soft">status: {rule.status}</span>}
            {rule.product && <span className="badge soft">{rule.product}</span>}
            {rule.service && <span className="badge soft">{rule.service}</span>}
            {rule.category && <span className="badge soft">{rule.category}</span>}
          </div>
          <div className="badge-row">
            {rule.mitre_tactics?.map((t: string) => <span className="badge" key={`ta-${t}`}>{t}</span>)}
            {rule.mitre_techniques?.map((t: string) => <span className="badge" key={`te-${t}`}>{t}</span>)}
            {!rule.mitre_tactics?.length && !rule.mitre_techniques?.length && <span className="faint small-text">No ATT&CK mapping</span>}
          </div>
        </div>

        <div className="card">
          <h3>Metadata</h3>
          <div className="kv"><span className="k">Quality score</span><span className="v" style={{ color: qualityColor(q) }}>{q} / 100</span></div>
          <div className="kv"><span className="k">Source</span><span className="v">{rule.source_repo}</span></div>
          {rule.source_path && <div className="kv"><span className="k">Path</span><span className="v mono" style={{ fontSize: 12, wordBreak: "break-all" }}>{rule.source_path}</span></div>}
          {rule.license && <div className="kv"><span className="k">License</span><span className="v">{rule.license}</span></div>}
          <div className="kv"><span className="k">Detection id</span><span className="v mono">#{rule.id}</span></div>
        </div>
      </section>

      <section className="card">
        <h3>Rule Definition</h3>
        <RuleCode rawYaml={rule.raw_yaml || ""} normalized={rule.normalized_json} />
      </section>
    </div>
  );
}
