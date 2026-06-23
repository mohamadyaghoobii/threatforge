"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import {
  IconOverview, IconShield, IconRules, IconLayers, IconTerminal,
  IconDashboard, IconCrosshair, IconRadar, IconGlobe, IconReport,
  IconDatabase, IconSettings,
} from "./icons";

type Item = { href: string; label: string; icon: ReactNode; tag?: string };
type Group = { label: string; items: Item[] };

const NAV: Group[] = [
  {
    label: "Operations",
    items: [
      { href: "/", label: "Overview", icon: <IconOverview /> },
      { href: "/mitre", label: "MITRE Coverage", icon: <IconShield /> },
      { href: "/rules", label: "Detection Rules", icon: <IconRules /> },
      { href: "/use-cases", label: "Use Cases", icon: <IconLayers /> },
    ],
  },
  {
    label: "Engineering",
    items: [
      { href: "/convert", label: "Query Generator", icon: <IconTerminal /> },
      { href: "/dashboards", label: "Dashboard Generator", icon: <IconDashboard /> },
      { href: "/atomic", label: "Adversary Emulation", icon: <IconCrosshair /> },
    ],
  },
  {
    label: "Intelligence",
    items: [
      { href: "/intel", label: "Threat Intel", icon: <IconRadar /> },
      { href: "/recon", label: "Attack Surface", icon: <IconGlobe /> },
    ],
  },
  {
    label: "Platform",
    items: [
      { href: "/reports", label: "Reports", icon: <IconReport /> },
      { href: "/sources", label: "Sources", icon: <IconDatabase /> },
      { href: "/settings", label: "Settings", icon: <IconSettings /> },
    ],
  },
];

function isActive(pathname: string, href: string) {
  if (href === "/") return pathname === "/";
  return pathname === href || pathname.startsWith(href + "/");
}

export default function Sidebar() {
  const pathname = usePathname() || "/";
  return (
    <aside className="sidebar">
      <Link href="/" className="brand">
        <span className="brand-mark">
          <IconShield width={19} height={19} />
        </span>
        <span className="brand-text">
          <span className="brand-name">MetaSec</span>
          <span className="brand-sub">Security Center</span>
        </span>
      </Link>

      <nav className="nav">
        {NAV.map((group) => (
          <div key={group.label}>
            <div className="nav-section">
              <span className="nav-section-label">{group.label}</span>
            </div>
            {group.items.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className={`nav-item${isActive(pathname, item.href) ? " active" : ""}`}
              >
                {item.icon}
                <span>{item.label}</span>
                {item.tag && <span className="nav-tag">{item.tag}</span>}
              </Link>
            ))}
          </div>
        ))}
      </nav>

      <div className="sidebar-foot">
        <div className="faint" style={{ fontSize: 11, lineHeight: 1.5 }}>
          Detection engineering &amp; threat intelligence platform.
        </div>
      </div>
    </aside>
  );
}
