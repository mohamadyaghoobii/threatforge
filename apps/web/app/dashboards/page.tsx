"use client";

import Link from "next/link";
import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  apiBase,
  DashboardCatalog,
  DashboardResult,
  FilterOptions,
  GenTarget,
  UseCase,
} from "../../lib/api";
import PageHeader from "../../components/PageHeader";
import { IconDashboard, IconTerminal } from "../../components/icons";

const emptyFilters: FilterOptions = {
  tactics: [], techniques: [], products: [], services: [], categories: [], severities: [], sources: [],
};

const LAYOUT_LABELS: Record<string, string> = {
  kill_chain: "Kill chain (by tactic)",
  by_severity: "By severity",
  by_data_source: "By data source",
  single_technique: "One panel per detection",
  grid: "Grid",
};

export default function DashboardsPage() {
  const [catalog, setCatalog] = useState<DashboardCatalog>({ targets: [], layouts: [] });
  const [filters, setFilters] = useState<FilterOptions>(emptyFilters);
  const [genTargets, setGenTargets] = useState<GenTarget[]>([]);
  const [useCases, setUseCases] = useState<UseCase[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [name, setName] = useState("My Threat Dashboard");
  const [tactic, setTactic] = useState("");
  const [technique, setTechnique] = useState("");
  const [severity, setSeverity] = useState("");
  const [target, setTarget] = useState("splunk");
  const [profile, setProfile] = useState<string>("");
  const [layout, setLayout] = useState("kill_chain");

  const [result, setResult] = useState<DashboardResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [genError, setGenError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        setLoading(true);
        const [cat, filt, tgts, ucs] = await Promise.all([
          fetch(`${apiBase}/api/dashboards/catalog`, { cache: "no-store" }).then((r) => r.json()),
          fetch(`${apiBase}/api/filters`, { cache: "no-store" }).then((r) => r.json()),
          fetch(`${apiBase}/api/generator/targets`, { cache: "no-store" }).then((r) => r.json()),
          fetch(`${apiBase}/api/use-cases?limit=1000`, { cache: "no-store" }).then((r) => r.json()),
        ]);
        setCatalog(cat);
        setFilters(filt);
        setGenTargets(tgts);
        setUseCases(ucs);
        if (cat.targets?.length) setTarget(cat.targets.includes("splunk") ? "splunk" : cat.targets[0]);
        if (cat.layouts?.length) setLayout(cat.layouts.includes("kill_chain") ? "kill_chain" : cat.layouts[0]);
        const params = new URLSearchParams(window.location.search);
        if (params.get("technique")) setTechnique(params.get("technique")!);
        else if (params.get("tactic")) setTactic(params.get("tactic")!);
      } catch (e) {
        setLoadError(e instanceof Error ? e.message : "Could not load catalog");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const profilesForTarget = useMemo(
    () => genTargets.find((t) => t.id === target)?.profiles ?? [],
    [genTargets, target]
  );

  useEffect(() => {
    if (profilesForTarget.length && !profilesForTarget.some((p) => p.id === profile)) {
      setProfile(profilesForTarget[0].id);
    }
    if (!profilesForTarget.length) setProfile("");
  }, [profilesForTarget, profile]);

  // Estimate how many detections match the chosen scope. A technique is
  // more specific than a tactic, so when one is chosen it takes precedence
  // (matches the backend builder).
  const matchCount = useMemo(() => {
    return useCases.reduce((sum, uc) => {
      if (technique) {
        if (uc.technique_id !== technique && uc.id !== technique) return sum;
      } else if (tactic) {
        if (!uc.tactics.includes(tactic)) return sum;
      }
      return sum + uc.rule_count;
    }, 0);
  }, [useCases, tactic, technique]);

  async function handleGenerate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setResult(null);
    setGenError(null);
    setCopied(false);
    if (!tactic && !technique) {
      setGenError("Choose at least a tactic or a technique to scope the dashboard.");
      return;
    }
    try {
      setBusy(true);
      const res = await fetch(`${apiBase}/api/dashboards/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          target,
          layout,
          profile: profile || null,
          scope: {
            tactics: tactic ? [tactic] : [],
            techniques: technique ? [technique] : [],
            severity: severity || null,
          },
          save: true,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : `HTTP ${res.status}`);
      setResult(data as DashboardResult);
    } catch (e) {
      setGenError(e instanceof Error ? e.message : "Generation failed");
    } finally {
      setBusy(false);
    }
  }

  function download() {
    if (!result) return;
    const blob = new Blob([result.artifact], { type: result.content_type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = result.filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function copyArtifact() {
    if (!result) return;
    await navigator.clipboard.writeText(result.artifact);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }

  return (
    <div className="grid">
      <PageHeader
        eyebrow="SIEM Export"
        icon={<IconDashboard />}
        title="Dashboard Generator"
        sub="Pick a MITRE tactic or technique, choose your SIEM, and generate a complete, import-ready dashboard built from every matching detection."
        actions={<Link className="button secondary" href="/convert"><IconTerminal /> Single Query</Link>}
      />

      {loadError && <div className="alert error">{loadError}</div>}
      {loading && <div className="alert">Loading catalog...</div>}

      <section className="cards generator-layout">
        <form className="card form-grid" onSubmit={handleGenerate}>
          <div>
            <h3>1 · Scope the problem</h3>
            <div className="muted">Choose the threat you want a dashboard for.</div>
          </div>

          <label className="field">
            <span>Dashboard name</span>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Execution Threats — Sysmon" />
          </label>

          <div className="inline-fields">
            <label className="field">
              <span>MITRE Tactic{technique ? " (overridden by technique)" : ""}</span>
              <select value={tactic} onChange={(e) => setTactic(e.target.value)} disabled={!!technique}>
                <option value="">Any tactic</option>
                {filters.tactics.map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
            </label>
            <label className="field">
              <span>MITRE Technique</span>
              <select value={technique} onChange={(e) => { setTechnique(e.target.value); if (e.target.value) setTactic(""); }}>
                <option value="">Any technique</option>
                {filters.techniques.map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
            </label>
          </div>

          <label className="field">
            <span>Severity (optional)</span>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">Any severity</option>
              {filters.severities.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>

          <div className="alert">{matchCount} detections match this scope.</div>

          <div>
            <h3>2 · Choose the SIEM &amp; layout</h3>
          </div>
          <div className="inline-fields">
            <label className="field">
              <span>Target SIEM</span>
              <select value={target} onChange={(e) => setTarget(e.target.value)}>
                {catalog.targets.map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
            </label>
            <label className="field">
              <span>Layout</span>
              <select value={layout} onChange={(e) => setLayout(e.target.value)}>
                {catalog.layouts.map((l) => <option key={l} value={l}>{LAYOUT_LABELS[l] || l}</option>)}
              </select>
            </label>
          </div>
          <label className="field">
            <span>Conversion profile</span>
            <select value={profile} onChange={(e) => setProfile(e.target.value)} disabled={!profilesForTarget.length}>
              {profilesForTarget.length === 0 && <option value="">target defaults</option>}
              {profilesForTarget.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          </label>

          {genError && <div className="alert error">{genError}</div>}
          <button className="button" type="submit" disabled={busy}>{busy ? "Generating dashboard..." : "Generate dashboard"}</button>
        </form>

        <section className="card form-grid">
          <h3>3 · Result</h3>
          {!result && <div className="muted">Your generated dashboard preview will appear here.</div>}
          {result && (
            <>
              <div className="selected-usecase">
                <div className="muted">Generated</div>
                <h2>{result.name}</h2>
                <div className="badge-row">
                  <span className="badge">{result.target}</span>
                  <span className="badge">{result.layout}</span>
                  <span className="badge">{result.format}</span>
                  <span className="badge">{result.panel_count} panels</span>
                </div>
              </div>
              <div className="result-header">
                <div className="muted">{result.filename}</div>
                <div className="hero-actions">
                  <button className="button" type="button" onClick={download}>Download</button>
                  <button className="button secondary" type="button" onClick={copyArtifact}>{copied ? "Copied" : "Copy"}</button>
                </div>
              </div>
              <div className="usecase-list" style={{ maxHeight: 220 }}>
                {result.panels.map((p, i) => (
                  <div key={i} className="usecase-item">
                    <div className="usecase-head">
                      <strong>{p.title}</strong>
                      <span>{p.viz}</span>
                    </div>
                    <div className="muted small-text">{[p.tactic, p.technique, p.severity].filter(Boolean).join(" · ")}</div>
                  </div>
                ))}
              </div>
              <pre className="code query-output" style={{ maxHeight: 300 }}>{result.artifact.slice(0, 4000)}{result.artifact.length > 4000 ? "\n... (download for full artifact)" : ""}</pre>
            </>
          )}
        </section>
      </section>
    </div>
  );
}
