import type { ReactNode } from "react";

export default function PageHeader({
  eyebrow, icon, title, sub, actions,
}: {
  eyebrow?: string;
  icon?: ReactNode;
  title: string;
  sub?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        {eyebrow && (
          <div className="page-eyebrow">
            {icon}
            {eyebrow}
          </div>
        )}
        <h1 className="page-title">{title}</h1>
        {sub && <p className="page-sub">{sub}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}
