"use client";

import Link from "next/link";
import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  apiBase, FilterOptions, GenConvertResponse, GenTarget, RuleListItem,
} from "../../lib/api";
import PageHeader from "../../components/PageHeader";
import {
  IconTerminal, IconDashboard, IconCopy, IconDownload, IconCheck, IconWarn, IconBolt,
} from "../../components/icons";

const emptyFilters: FilterOptions = {
  tactics: [], techniques: [], products: [], services: [], categories: [], severities: [], sources: [],
};

type Confidence = "high" | "medium" | "low";

function confidenceOf(result: GenConvertResponse | null): Confidence {
  if (!result) return "medium";
  const ok = result.status === "ok" || result.status === "success";
  if (!ok || result.error) return "low";
  const serious = result.warnings.some((w) =>
    ["error", "high", "critical"].includes((w.severity || "").toLowerCase()));
  if (serious) return "low";
  return result.warnings.length ? "medium" : "high";
}

export default function ConvertPage() {
  const [rules, setRules] = useState<RuleListItem[]>([]);
  const [targets, setTargets] = useState<GenTarget[]>([]);
  const [filters, setFilters] = useState<FilterOptions>(emptyFilters);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [query, setQuery] = useState("");
  const [tactic, setTactic] = useState("");
  const [technique, setTechnique] = useState("");
  const [severity, setSeverity] = useState("");
  const [product, setProduct] = useState("");
  const [source, setSource] = useState("");

  const [ruleId, setRuleId] = useState("");
  const [targetId, setTargetId] = useState("splunk");
  const [profileId, setProfileId] = useState("");
  const [outputFormat, setOutputFormat] = useState("spl");

  const [result, setResult] = useState<GenConvertResponse | null>(null);
  const [explanation, setExplanation] = useState("");
  const [busy, setBusy] = useState(false);
  const [convertError, setConvertError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        setLoading(true);
        const [rulesRes, targetsRes, filtersRes] = await Promise.all([
          fetch(`${apiBase}/api/rules?limit=1000`, { cache: "no-store" }).then((r) => r.json()),
          fetch(`${apiBase}/api/generator/targets`, { cache: "no-store" }).then((r) => r.json()),
          fetch(`${apiBase}/api/filters`, { cache: "no-store" }).then((r) => r.json()),
        ]);
        setRules(rulesRes);
        setTargets(targetsRes);
        setFilters(filtersRes);
        const params = new URLSearchParams(window.location.search);
        const preRule = params.get("rule");
        if (preRule && rulesRes.some((r: RuleListItem) => String(r.id) === preRule)) setRuleId(preRule);
        else if (rulesRes.length) setRuleId(String(rulesRes[0].id));
        if (params.get("tactic")) setTactic(params.get("tactic")!);
        if (params.get("technique")) setTechnique(params.get("technique")!);
      } catch (e) {
        setLoadError(e instanceof Error ? e.message : "Could not load generator data");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const selectedTarget = useMemo(() => targets.find((t) => t.id === targetId), [targets, targetId]);

  useEffect(() => {
    const profiles = selectedTarget?.profiles ?? [];
    if (profiles.length && !profiles.some((p) => p.id === profileId)) setProfileId(profiles[0].id);
    if (!profiles.length) setProfileId("");
    const formats = selectedTarget?.formats ?? [];
    if (formats.length && !formats.some((f) => f.id === outputFormat)) setOutputFormat(formats[0].id);
  }, [selectedTarget, profileId, outputFormat]);

  const filteredRules = useMemo(() => {
    const v = query.trim().toLowerCase();
    return rules.filter((r) => {
      if (tactic && !r.mitre_tactics.includes(tactic)) return false;
      if (technique && !r.mitre_techniques.includes(technique)) return false;
      if (severity && r.severity !== severity) return false;
      if (product && r.product !== product) return false;
      if (source && r.source_repo !== source) return false;
      if (!v) return true;
      return [r.title, r.source_repo, r.severity || "", r.product || "", ...r.mitre_techniques].join(" ").toLowerCase().includes(v);
    });
  }, [rules, query, tactic, technique, severity, product, source]);

  useEffect(() => {
    if (filteredRules.length && !filteredRules.some((r) => String(r.id) === ruleId)) {
      setRuleId(String(filteredRules[0].id));
    }
  }, [filteredRules, ruleId]);

  const selectedRule = rules.find((r) => String(r.id) === ruleId) || null;
  const selectedFormat = useMemo(
    () => selectedTarget?.formats.find((f) => f.id === outputFormat),
    [selectedTarget, outputFormat],
  );

  async function handleConvert(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setResult(null);
    setExplanation("");
    setConvertError(null);
    setCopied(false);
    if (!ruleId) { setConvertError("No rule selected."); return; }
    try {
      setBusy(true);
      const res = await fetch(`${apiBase}/api/generator/preview`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rule_id: Number(ruleId), target: targetId, profile: profileId || null, output_format: outputFormat }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : `HTTP ${res.status}`);
      setResult(data as GenConvertResponse);
    } catch (e) {
      setConvertError(e instanceof Error ? e.message : "Conversion failed");
    } finally {
      setBusy(false);
    }
  }

  async function explain() {
    if (!result?.query) return;
    const res = await fetch(`${apiBase}/api/generator/explain`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: result.target, query: result.query }),
    });
    if (res.ok) setExplanation((await res.json()).explanation || "");
  }

  async function copyQuery() {
    if (!result?.query) return;
    try {
      await navigator.clipboard.writeText(result.query);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch { /* clipboard unavailable */ }
  }

  function exportQuery() {
    if (!result?.query) return;
    const ext = selectedFormat?.file_extension?.replace(/^\./, "") || "txt";
    const type = selectedFormat?.content_type || "text/plain";
    const blob = new Blob([result.query], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${result.target}_${result.rule_id}.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const conf = confidenceOf(result);
  const confLabel = conf === "high" ? "High confidence" : conf === "medium" ? "Review recommended" : "Manual review required";

  return (
    <div className="grid">
      <PageHeader
        eyebrow="SIEM Conversion"
        icon={<IconTerminal />}
        title="Query Generator"
        sub={`Convert any normalized detection into a SIEM-native query. ${targets.length || "Multiple"} targets, per-product profiles, native output formats, structured conversion warnings, and plain-English explanations.`}
        actions={<Link className="button secondary" href="/dashboards"><IconDashboard /> Dashboard Generator</Link>}
      />

      {loadError && <div className="alert error"><strong>Could not reach the generator API.</strong><span>{loadError}</span></div>}
      {loading && (
        <div className="card"><div className="skeleton skeleton-row" style={{ width: "40%" }} /><div className="skeleton skeleton-row" /><div className="skeleton skeleton-row" style={{ width: "75%" }} /></div>
      )}

      {!loading && (
        <>
          {/* Scope */}
          <section className="card form-grid">
            <div className="section-title-row">
              <div>
                <h3>1 · Select a detection</h3>
                <div className="muted">Filter the corpus, then choose the rule you want to convert.</div>
              </div>
              <div className="muted">{filteredRules.length} of {rules.length} rules</div>
            </div>
            <div className="filter-grid">
              <label className="field span-2"><span>Search</span>
                <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="T1059, PowerShell, sysmon, mimikatz…" />
              </label>
              <label className="field"><span>Tactic</span>
                <select value={tactic} onChange={(e) => setTactic(e.target.value)}>
                  <option value="">All tactics</option>{filters.tactics.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
              </label>
              <label className="field"><span>Technique</span>
                <select value={technique} onChange={(e) => setTechnique(e.target.value)}>
                  <option value="">All techniques</option>{filters.techniques.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
              </label>
              <label className="field"><span>Severity</span>
                <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
                  <option value="">All</option>{filters.severities.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
              </label>
              <label className="field"><span>Product</span>
                <select value={product} onChange={(e) => setProduct(e.target.value)}>
                  <option value="">All</option>{filters.products.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
              </label>
              <label className="field"><span>Source</span>
                <select value={source} onChange={(e) => setSource(e.target.value)}>
                  <option value="">All</option>{filters.sources.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
              </label>
            </div>
          </section>

          <section className="cards generator-layout">
            {/* Configure */}
            <form className="card form-grid" onSubmit={handleConvert}>
              <h3>2 · Configure conversion</h3>
              <label className="field"><span>Detection rule</span>
                <select value={ruleId} onChange={(e) => setRuleId(e.target.value)} disabled={!filteredRules.length}>
                  {filteredRules.slice(0, 500).map((r) => (
                    <option key={r.id} value={r.id}>#{r.id} · Q{r.quality_score} · {r.title} · {r.source_repo}</option>
                  ))}
                </select>
              </label>
              {selectedRule && (
                <div className="rule-summary">
                  <h2 style={{ fontSize: 16 }}>{selectedRule.title}</h2>
                  <div className="badge-row">
                    <span className={`sev sev-${(selectedRule.severity || "unknown").toLowerCase()}`}>{selectedRule.severity || "unknown"}</span>
                    {selectedRule.product && <span className="badge soft">{selectedRule.product}</span>}
                    {selectedRule.mitre_techniques.slice(0, 4).map((t) => <span className="badge" key={t}>{t}</span>)}
                  </div>
                </div>
              )}
              <div className="inline-fields">
                <label className="field"><span>SIEM target</span>
                  <select value={targetId} onChange={(e) => setTargetId(e.target.value)}>
                    {targets.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
                  </select>
                </label>
                <label className="field"><span>Output format</span>
                  <select value={outputFormat} onChange={(e) => setOutputFormat(e.target.value)}>
                    {(selectedTarget?.formats || []).map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}
                  </select>
                </label>
              </div>
              <label className="field"><span>Conversion profile</span>
                <select value={profileId} onChange={(e) => setProfileId(e.target.value)} disabled={!(selectedTarget?.profiles?.length)}>
                  {(selectedTarget?.profiles?.length ? selectedTarget.profiles : [{ id: "", name: "target defaults" }]).map((p) => (
                    <option key={p.id} value={p.id}>{p.name}</option>
                  ))}
                </select>
              </label>
              {convertError && <div className="alert error">{convertError}</div>}
              <button className="button" type="submit" disabled={busy || !ruleId}>
                <IconBolt /> {busy ? "Generating…" : "Generate query"}
              </button>
            </form>

            {/* Result */}
            <section className="card form-grid">
              <div className="card-head">
                <h3>3 · Generated query</h3>
                {result && (
                  <div className={`confidence ${conf}`} title="Conversion confidence">
                    <span className="confidence-bars"><i /><i /><i /></span>
                    <span className="muted small-text" style={{ margin: 0 }}>{confLabel}</span>
                  </div>
                )}
              </div>

              {!result && !busy && (
                <div className="empty" style={{ padding: "32px 16px" }}>
                  <div className="empty-icon"><IconTerminal /></div>
                  <h3>No query yet</h3>
                  <p>Pick a detection, target, and profile, then generate. The query, backend, and any conversion warnings appear here.</p>
                </div>
              )}
              {busy && <div className="skeleton skeleton-row" style={{ height: 120 }} />}

              {result && (
                <>
                  <div className="badge-row">
                    <span className="badge">{result.target}</span>
                    {result.profile && <span className="badge soft">{result.profile}</span>}
                    <span className="badge soft">{result.output_format}</span>
                    {result.backend && <span className="badge tech">backend: {result.backend}</span>}
                  </div>
                  <div className="result-header">
                    <div className="muted small-text" style={{ margin: 0 }}>Source: detection #{result.rule_id}</div>
                    <div className="badge-row">
                      <button className="button secondary sm" type="button" onClick={copyQuery}>{copied ? <IconCheck /> : <IconCopy />} {copied ? "Copied" : "Copy"}</button>
                      <button className="button secondary sm" type="button" onClick={exportQuery}><IconDownload /> Export</button>
                      <button className="button ghost sm" type="button" onClick={explain}>Explain</button>
                    </div>
                  </div>
                  <pre className="code query-output">{result.query}</pre>
                  {explanation && <div className="alert"><strong>Explanation</strong><div>{explanation}</div></div>}
                  {result.warnings.length > 0 ? (
                    <div className="alert warn">
                      <strong style={{ display: "flex", alignItems: "center", gap: 6 }}><IconWarn /> Conversion warnings ({result.warnings.length})</strong>
                      <ul>
                        {result.warnings.map((w, i) => (
                          <li key={i}><code>{w.code}</code> · {w.severity} — {w.message}{w.suggestion ? ` (${w.suggestion})` : ""}</li>
                        ))}
                      </ul>
                    </div>
                  ) : (
                    <div className="alert success"><strong>Clean conversion</strong><span>No assumptions or warnings were recorded for this rule and target.</span></div>
                  )}
                </>
              )}
            </section>
          </section>
        </>
      )}
    </div>
  );
}
