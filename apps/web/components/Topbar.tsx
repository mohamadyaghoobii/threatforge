"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getHealth } from "../lib/api";
import { IconSearch } from "./icons";

type HealthState = "loading" | "ok" | "down";

export default function Topbar() {
  const router = useRouter();
  const [q, setQ] = useState("");
  const [health, setHealth] = useState<HealthState>("loading");
  const [env, setEnv] = useState<string>("");

  useEffect(() => {
    let alive = true;
    async function ping() {
      try {
        const h = await getHealth();
        if (!alive) return;
        if (h?.status === "ok") { setHealth("ok"); setEnv(h.env || ""); }
        else setHealth("down");
      } catch { if (alive) setHealth("down"); }
    }
    ping();
    const t = setInterval(ping, 30000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const v = q.trim();
    router.push(v ? `/rules?q=${encodeURIComponent(v)}` : "/rules");
  }

  const dotClass = health === "ok" ? "" : health === "down" ? "down" : "idle";
  const label = health === "ok" ? "Operational" : health === "down" ? "API offline" : "Checking…";

  return (
    <header className="topbar">
      <form className="topbar-search" onSubmit={submit} role="search">
        <IconSearch />
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search detections, techniques, sources…"
          aria-label="Search"
          style={{ all: "unset", flex: 1, color: "var(--text)", fontSize: 13 }}
        />
        <kbd>↵</kbd>
      </form>

      <div className="topbar-right">
        {env && <span className="env-pill">{env === "local" ? "Local Workspace" : env}</span>}
        <span className="env-pill" title="Backend API status">
          <span className={`status-dot ${dotClass}`} />
          {label}
        </span>
      </div>
    </header>
  );
}
