import { mergeVuln } from "@/lib/merge-vuln";
import { searchNist } from "@/lib/nist";
import { searchOsv } from "@/lib/osv";
import type { Vuln } from "@/lib/types";

export type AdvisorySearch = {
  query: string;
  ok: boolean;
  error?: string;
  note: string;
  vulnerabilities: Vuln[];
};

function noteFor(label: string, hit: { ok: boolean; error?: string; vulnerabilities: Vuln[] }): string {
  return hit.ok ? `${hit.vulnerabilities.length} no ${label}` : (hit.error ?? `${label} não respondeu.`);
}

export async function searchPublic(raw: string): Promise<AdvisorySearch> {
  const [nist, osv] = await Promise.all([searchNist(raw), searchOsv(raw)]);
  const byId = new Map<string, Vuln>();
  for (const item of [...nist.vulnerabilities, ...osv.vulnerabilities]) {
    const existing = byId.get(item.id);
    byId.set(item.id, existing ? mergeVuln(existing, item) : item);
  }
  const ok = nist.ok || osv.ok;
  return {
    query: raw.trim(),
    ok,
    error: ok ? undefined : "O NIST e o OSV.dev não responderam.",
    note: `${noteFor("NIST", nist)} · ${noteFor("OSV.dev", osv)} · o VulDB desta página é o da coleta publicada`,
    vulnerabilities: [...byId.values()].sort((a, b) => b.published.localeCompare(a.published)).slice(0, 20),
  };
}
