const apiBase = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

/**
 * Resilient GET helper. Returns the typed `fallback` on any failure — a non-OK
 * response OR a thrown network error (e.g. the API is offline). This keeps the
 * portal rendering its empty/error states instead of crashing the page when the
 * backend is unavailable, which is the common case during local development.
 */
async function getJSON<T>(path: string, fallback: T): Promise<T> {
  try {
    const res = await fetch(`${apiBase}${path}`, { cache: "no-store" });
    if (!res.ok) return fallback;
    return (await res.json()) as T;
  } catch {
    return fallback;
  }
}

export type RuleListItem = {
  id: number;
  title: string;
  severity: string | null;
  product: string | null;
  service: string | null;
  category: string | null;
  mitre_tactics: string[];
  mitre_techniques: string[];
  source_repo: string;
  quality_score: number;
};

export type Repository = {
  id: number | null;
  name: string;
  url: string;
  branch: string;
  type: string;
  license: string | null;
  enabled: boolean;
  last_commit_hash: string | null;
  last_sync_status: string | null;
  last_sync_error: string | null;
};

export type TargetProfile = {
  id: string;
  name: string;
};

export type Target = {
  id: string;
  name: string;
  support_level: string;
  profiles: TargetProfile[];
  formats: string[];
};

export type FilterOptions = {
  tactics: string[];
  techniques: string[];
  products: string[];
  services: string[];
  categories: string[];
  severities: string[];
  sources: string[];
};

export type UseCase = {
  id: string;
  technique_id: string | null;
  name: string;
  tactics: string[];
  platforms: string[];
  products: string[];
  categories: string[];
  sources: string[];
  severities: Record<string, number>;
  rule_count: number;
  best_rule_id: number | null;
  best_rule_title: string | null;
  best_quality_score: number;
  target_support: string[];
};

export type PlatformStats = {
  rules: number;
  repositories: number;
  techniques: number;
  tactics: number;
};

const emptyFilterOptions: FilterOptions = {
  tactics: [], techniques: [], products: [], services: [], categories: [], severities: [], sources: [],
};

export async function getHealth() {
  return getJSON<{ status: string; app?: string; env?: string } | null>("/health", null);
}

export async function getStats(): Promise<PlatformStats> {
  return getJSON<PlatformStats>("/api/stats", { rules: 0, repositories: 0, techniques: 0, tactics: 0 });
}

export async function getRepositories(): Promise<Repository[]> {
  return getJSON<Repository[]>("/api/repositories", []);
}

export async function getRules(): Promise<RuleListItem[]> {
  return getJSON<RuleListItem[]>("/api/rules?limit=500", []);
}

export async function getTactics(): Promise<{ tactic: string; rule_count: number }[]> {
  return getJSON("/api/mitre/tactics", []);
}

export async function getTechniques(): Promise<{ technique_id: string; rule_count: number }[]> {
  return getJSON("/api/mitre/techniques", []);
}

export async function getTargets(): Promise<Target[]> {
  return getJSON<Target[]>("/api/catalog/targets", []);
}

export async function getFilterOptions(): Promise<FilterOptions> {
  return getJSON<FilterOptions>("/api/filters", emptyFilterOptions);
}

export async function getUseCases(): Promise<UseCase[]> {
  return getJSON<UseCase[]>("/api/use-cases?limit=1000", []);
}

// --- Generator V2 -----------------------------------------------------------

export type GenFormat = {
  id: string;
  name: string;
  description: string;
  support_level: string;
  content_type: string;
  file_extension: string;
};

export type GenProfile = {
  id: string;
  name: string;
  description: string | null;
  audience: string | null;
  output_formats: string[];
};

export type GenTarget = {
  id: string;
  name: string;
  description: string;
  aliases: string[];
  formats: GenFormat[];
  profiles: GenProfile[];
};

export type GenWarning = {
  code: string;
  severity: string;
  message: string;
  field: string | null;
  suggestion: string | null;
};

export type GenConvertResponse = {
  rule_id: number;
  target: string;
  profile: string | null;
  output_format: string;
  query: string;
  status: string;
  warnings: GenWarning[];
  error: string | null;
  backend: string | null;
  metadata: Record<string, unknown>;
};

export async function getGeneratorTargets(): Promise<GenTarget[]> {
  return getJSON<GenTarget[]>("/api/generator/targets", []);
}

export async function generatorConvert(body: {
  rule_id: number;
  target: string;
  profile?: string | null;
  output_format: string;
}): Promise<GenConvertResponse> {
  const res = await fetch(`${apiBase}/api/generator/preview`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : `HTTP ${res.status}`);
  return data as GenConvertResponse;
}

export async function generatorExplain(target: string, query: string): Promise<string> {
  try {
    const res = await fetch(`${apiBase}/api/generator/explain`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, query }),
    });
    if (!res.ok) return "";
    const data = await res.json();
    return data.explanation || "";
  } catch {
    return "";
  }
}

// --- Dashboard generator ----------------------------------------------------

export type DashboardCatalog = { targets: string[]; layouts: string[] };

export type DashboardPanel = {
  title: string;
  technique: string | null;
  tactic: string | null;
  severity: string | null;
  viz: string;
  backend: string | null;
};

export type DashboardResult = {
  id: number | null;
  name: string;
  target: string;
  layout: string;
  format: string;
  content_type: string;
  filename: string;
  panel_count: number;
  artifact: string;
  panels: DashboardPanel[];
};

export type DashboardSummary = {
  id: number;
  name: string;
  target: string;
  layout: string;
  output_format: string;
  panel_count: number;
  created_at: string | null;
};

export async function getDashboardCatalog(): Promise<DashboardCatalog> {
  return getJSON<DashboardCatalog>("/api/dashboards/catalog", { targets: [], layouts: [] });
}

export async function generateDashboard(body: {
  name: string;
  target: string;
  layout: string;
  profile?: string | null;
  scope: { tactics?: string[]; techniques?: string[]; rule_ids?: number[]; severity?: string | null };
  save?: boolean;
}): Promise<DashboardResult> {
  const res = await fetch(`${apiBase}/api/dashboards/generate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : `HTTP ${res.status}`);
  return data as DashboardResult;
}

export async function listDashboards(): Promise<DashboardSummary[]> {
  return getJSON<DashboardSummary[]>("/api/dashboards", []);
}

// --- Threat Intelligence ----------------------------------------------------

export type IntelStats = {
  indicators: number;
  indicators_active: number;
  user_agents: number;
  by_type: Record<string, number>;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  by_source: Record<string, number>;
  ua_by_severity: Record<string, number>;
};

export type Indicator = {
  id: number;
  ioc: string;
  normalized: string;
  ioc_type: string;
  threat_score: number;
  severity: string;
  confidence: string;
  category: string;
  tags: string[];
  sources: string[];
  first_seen: string | null;
  last_seen: string | null;
  is_active: boolean;
};

export type UserAgentRow = {
  id: number;
  user_agent: string;
  tool_name: string;
  category: string;
  severity: string;
  sources: string[];
};

export async function getIntelStats(): Promise<IntelStats | null> {
  return getJSON<IntelStats | null>("/api/intel/stats", null);
}

export async function getIndicators(params: string): Promise<Indicator[]> {
  return getJSON<Indicator[]>(`/api/intel/iocs?${params}`, []);
}

export async function getUserAgents(params: string): Promise<UserAgentRow[]> {
  return getJSON<UserAgentRow[]>(`/api/intel/useragents?${params}`, []);
}

// --- Live system status (centralized) ---------------------------------------

export type SystemMode = "live" | "degraded" | "offline";

export type SyncSource = {
  name: string;
  type: string;
  enabled: boolean;
  status: string; // success | error | pending | disabled
  lastCommit: string | null;
  error: string | null;
};

export type ReconCapabilities = {
  renderingAvailable: boolean;
  scans: number;
  avgScore: number | null;
};

export type SystemStatus = {
  apiOnline: boolean;
  dbConnected: boolean;
  env: string | null;
  mode: SystemMode;
  ruleCount: number;
  sourceCount: number;
  sourcesOk: number;
  sourcesFailed: number;
  sources: SyncSource[];
  lastImport: string | null; // backend does not track this yet → placeholder
  nextSync: string | null; // scheduler not enabled yet → placeholder
  latestRecon: { target: string; grade: string | null; score: number | null; status: string | null } | null;
  latestDashboard: { name: string; target: string; createdAt: string | null } | null;
};

/** Like getJSON but reports whether the call actually succeeded, so callers can
 *  tell "API offline" apart from "API online but empty". */
async function tryJSON<T>(path: string): Promise<{ ok: boolean; data: T | null }> {
  try {
    const res = await fetch(`${apiBase}${path}`, { cache: "no-store" });
    if (!res.ok) return { ok: false, data: null };
    return { ok: true, data: (await res.json()) as T };
  } catch {
    return { ok: false, data: null };
  }
}

export async function getReconCapabilities(): Promise<ReconCapabilities> {
  const { ok, data } = await tryJSON<{ selenium_available?: boolean; scans?: number; avg_score?: number }>("/api/recon/stats");
  if (!ok || !data) return { renderingAvailable: false, scans: 0, avgScore: null };
  return {
    renderingAvailable: Boolean(data.selenium_available),
    scans: Number(data.scans ?? 0),
    avgScore: data.avg_score ?? null,
  };
}

export async function getSystemStatus(): Promise<SystemStatus> {
  const [health, stats, repos, recon, dashboards] = await Promise.all([
    tryJSON<{ status: string; env?: string }>("/health"),
    tryJSON<PlatformStats>("/api/stats"),
    tryJSON<Repository[]>("/api/repositories"),
    tryJSON<Array<{ target: string; grade?: string; score?: number; status?: string }>>("/api/recon/scans?limit=1"),
    tryJSON<DashboardSummary[]>("/api/dashboards"),
  ]);

  const apiOnline = health.ok && health.data?.status === "ok";
  const dbConnected = stats.ok;
  const ruleCount = stats.data?.rules ?? 0;

  const sources: SyncSource[] = (repos.data ?? []).map((r) => ({
    name: r.name,
    type: r.type,
    enabled: r.enabled,
    status: !r.enabled ? "disabled" : r.last_sync_status || "pending",
    lastCommit: r.last_commit_hash,
    error: r.last_sync_error,
  }));
  const sourcesOk = sources.filter((s) => s.status === "success" || s.status === "ok").length;
  const sourcesFailed = sources.filter((s) => s.status === "error").length;

  const reconRow = recon.data?.[0] ?? null;
  const latestRecon = reconRow
    ? { target: reconRow.target, grade: reconRow.grade ?? null, score: reconRow.score ?? null, status: reconRow.status ?? null }
    : null;

  const dashList = dashboards.data ?? [];
  const latestDashboard = dashList.length
    ? (() => {
        const d = [...dashList].sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""))[0];
        return { name: d.name, target: d.target, createdAt: d.created_at };
      })()
    : null;

  const mode: SystemMode = !apiOnline ? "offline" : ruleCount === 0 || sourcesFailed > 0 ? "degraded" : "live";

  return {
    apiOnline,
    dbConnected,
    env: health.data?.env ?? null,
    mode,
    ruleCount,
    sourceCount: sources.length,
    sourcesOk,
    sourcesFailed,
    sources,
    lastImport: null,
    nextSync: null,
    latestRecon,
    latestDashboard,
  };
}

export { apiBase };
