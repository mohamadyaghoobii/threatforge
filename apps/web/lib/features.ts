/**
 * Centralized feature flags for the MetaSec Security Center frontend.
 *
 * These describe capability *intent* and configuration — they never fabricate
 * results. AI defaults to "disabled" and the app is fully functional without it.
 * Override the AI provider at deploy time with NEXT_PUBLIC_AI_PROVIDER.
 */

export type AiProvider = "disabled" | "rule_based" | "local_ollama" | "local_transformers";

const AI_PROVIDER_VALUES: AiProvider[] = ["disabled", "rule_based", "local_ollama", "local_transformers"];

const rawProvider = (process.env.NEXT_PUBLIC_AI_PROVIDER || "disabled").toLowerCase();
export const AI_PROVIDER: AiProvider = (AI_PROVIDER_VALUES as string[]).includes(rawProvider)
  ? (rawProvider as AiProvider)
  : "disabled";

export const AI_ENABLED = AI_PROVIDER !== "disabled";

export const AI_PROVIDER_LABEL: Record<AiProvider, string> = {
  disabled: "Disabled",
  rule_based: "Rule-based (heuristic, no model)",
  local_ollama: "Local — Ollama",
  local_transformers: "Local — Transformers",
};

export const FEATURES = {
  ai: {
    enabled: AI_ENABLED,
    provider: AI_PROVIDER,
    /** Whether a local AI runtime is wired up. Local providers are treated as
     *  "configured" only when explicitly selected; paid/cloud APIs are not used. */
    localConfigured: AI_PROVIDER === "local_ollama" || AI_PROVIDER === "local_transformers",
    planned: [
      "Detection rule explanation assist",
      "Use-case and gap summarization",
      "Conversion warning guidance",
      "Natural-language rule search",
    ],
  },
  automation: {
    /** Real availability is resolved at runtime from the recon engine
     *  (/api/recon/stats.selenium_available); this is the product intent. */
    reconRenderingSupported: true,
    aggressiveScanning: false,
  },
  scheduler: {
    enabled: false,
    planned: true,
  },
  reports: {
    exportPdf: false,
    exportMarkdown: false,
    exportJson: false,
  },
} as const;
