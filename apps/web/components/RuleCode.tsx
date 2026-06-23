"use client";

import { useState } from "react";
import { IconCopy, IconCheck } from "./icons";

export default function RuleCode({ rawYaml, normalized }: { rawYaml: string; normalized: unknown }) {
  const [tab, setTab] = useState<"yaml" | "json">("yaml");
  const [copied, setCopied] = useState(false);

  const jsonText = JSON.stringify(normalized ?? {}, null, 2);
  const text = tab === "yaml" ? rawYaml : jsonText;

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch { /* clipboard unavailable */ }
  }

  return (
    <div className="form-grid" style={{ gap: 12 }}>
      <div className="result-header">
        <div className="segmented">
          <button className={tab === "yaml" ? "active" : ""} onClick={() => setTab("yaml")}>Raw YAML</button>
          <button className={tab === "json" ? "active" : ""} onClick={() => setTab("json")}>Normalized JSON</button>
        </div>
        <button className="button secondary sm" type="button" onClick={copy}>
          {copied ? <IconCheck /> : <IconCopy />} {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="code query-output" style={{ maxHeight: 560 }}>{text}</pre>
    </div>
  );
}
