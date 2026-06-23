import { getUseCases, getFilterOptions } from "../../lib/api";
import PageHeader from "../../components/PageHeader";
import UseCasesExplorer from "../../components/UseCasesExplorer";
import { IconLayers } from "../../components/icons";

export default async function UseCasesPage({
  searchParams,
}: {
  searchParams: Promise<{ focus?: string }>;
}) {
  const { focus } = await searchParams;
  const [useCases, filters] = await Promise.all([getUseCases(), getFilterOptions()]);

  return (
    <div className="grid">
      <PageHeader
        eyebrow="Use-Case First"
        icon={<IconLayers />}
        title="Detection Use Cases"
        sub="Detections grouped by ATT&CK technique. Each use case can have many rule variants across sources — compare coverage and quality, then generate a SIEM query for the best candidate."
      />
      <UseCasesExplorer useCases={useCases} filters={filters} focus={focus || ""} />
    </div>
  );
}
