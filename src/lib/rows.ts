import { writeBriefing, type BriefingInput } from "@/lib/briefing";
import { assess, type Match } from "@/lib/match";
import type { Asset, TriageEntry, TriageStatus, Vuln } from "@/lib/types";
import { daysBetween } from "@/lib/text";

export type Row = {
  vuln: Vuln;
  match: Match;
  status: TriageStatus;
  note: string;
};

const CLOSED = new Set<TriageStatus>(["mitigada", "nao-afeta", "risco-aceito"]);

export function buildRows(
  vulnerabilities: Vuln[],
  assets: Asset[],
  triage: Record<string, TriageEntry>,
  today: string,
): Row[] {
  return vulnerabilities
    .map((vuln) => ({
      vuln,
      match: assess(vuln, assets, today),
      status: triage[vuln.id]?.status ?? "nova",
      note: triage[vuln.id]?.note ?? "",
    }))
    .sort((a, b) => b.match.score - a.match.score || b.vuln.published.localeCompare(a.vuln.published));
}

export function describePlantao(rows: Row[], today: string): { text: string; stats: BriefingInput } {
  const kevRecent = rows.filter(
    (row) => row.vuln.kev && daysBetween(today, row.vuln.published) <= 7 && daysBetween(today, row.vuln.published) >= 0,
  ).length;
  const matchedRows = rows.filter((row) => row.match.assets.length > 0);
  const matchedEssential = matchedRows.filter((row) =>
    row.match.assets.some((asset) => asset.criticality === "essencial"),
  ).length;
  const openTriage = rows.filter((row) => row.status === "nova").length;
  const overdue = rows.filter((row) => {
    if (!row.vuln.kev || !row.vuln.dueDate || row.match.assets.length === 0) return false;
    if (CLOSED.has(row.status)) return false;
    return daysBetween(row.vuln.dueDate, today) < 0;
  }).length;
  const top = rows.find((row) => !CLOSED.has(row.status) && (row.match.assets.length > 0 || row.vuln.kev));
  const stats: BriefingInput = {
    kevRecent,
    matched: matchedRows.length,
    matchedEssential,
    openTriage,
    overdue,
    top: top
      ? { id: top.vuln.id, vendor: top.vuln.vendor, product: top.vuln.product }
      : null,
  };
  return { text: writeBriefing(stats), stats };
}

export type QueueFilter = "olhar" | "kev" | "ativos" | "tudo";

export function filterRows(rows: Row[], filter: QueueFilter, query: string): Row[] {
  const needle = query.trim().toLowerCase();
  return rows.filter((row) => {
    if (needle) {
      const hay = `${row.vuln.id} ${row.vuln.vendor} ${row.vuln.product} ${row.vuln.name}`.toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    if (filter === "kev") return row.vuln.kev;
    if (filter === "ativos") return row.match.assets.length > 0;
    if (filter === "olhar") {
      const open = row.status === "nova" || row.status === "em-analise" || row.status === "afeta";
      const relevant =
        row.vuln.kev ||
        row.match.assets.length > 0 ||
        row.vuln.severity === "critical" ||
        row.vuln.severity === "high";
      return open && relevant;
    }
    return true;
  });
}
