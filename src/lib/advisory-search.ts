import { mergeVuln } from "@/lib/merge-vuln";
import { searchPublic } from "@/lib/public-search";
import type { Vuln } from "@/lib/types";
import { searchVuldb } from "@/lib/vuldb";

export async function searchAdvisories(raw: string) {
  const [pub, vuldb] = await Promise.all([searchPublic(raw), searchVuldb(raw)]);
  const byId = new Map<string, Vuln>(pub.vulnerabilities.map((item) => [item.id, item]));
  for (const item of vuldb.vulnerabilities) {
    const existing = byId.get(item.id);
    byId.set(item.id, existing ? mergeVuln(existing, item) : item);
  }
  const vuldbNote = vuldb.ok
    ? `${vuldb.vulnerabilities.length} no VulDB`
    : vuldb.error === "O VulDB precisa da chave VULDB_API_KEY."
      ? "o VulDB desta consulta é o da coleta publicada"
      : vuldb.error;
  const note = [pub.note.replace(" · o VulDB desta página é o da coleta publicada", ""), vuldbNote]
    .filter(Boolean)
    .join(" · ");
  const ok = pub.ok || vuldb.ok;
  return {
    query: raw.trim(),
    ok,
    error: ok ? undefined : "NIST, OSV.dev e VulDB não responderam.",
    note,
    vulnerabilities: [...byId.values()].sort((a, b) => b.published.localeCompare(a.published)).slice(0, 20),
  };
}
