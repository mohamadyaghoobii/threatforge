import Link from "next/link";
import { getUseCases, getFilterOptions } from "../../lib/api";
import PageHeader from "../../components/PageHeader";
import MitreMatrix from "../../components/MitreMatrix";
import { IconShield, IconTerminal } from "../../components/icons";

export default async function MitrePage({
  searchParams,
}: {
  searchParams: Promise<{ tactic?: string }>;
}) {
  const { tactic } = await searchParams;
  const [useCases, filters] = await Promise.all([getUseCases(), getFilterOptions()]);

  return (
    <div className="grid">
      <PageHeader
        eyebrow="ATT&CK Coverage"
        icon={<IconShield />}
        title="MITRE ATT&CK Coverage"
        sub="Detection coverage across the ATT&CK kill chain. Each cell is a technique; intensity reflects how many normalized detections back it. Filter by product, source, or severity to find gaps."
        actions={<Link className="button secondary" href="/convert"><IconTerminal /> Query Generator</Link>}
      />
      <MitreMatrix useCases={useCases} filters={filters} initialTactic={tactic || ""} />
    </div>
  );
}
