import { collectLinks } from "@/lib/links";
import { remediationFor } from "@/lib/remediation";
import type { Severity, SourceReport, Vuln } from "@/lib/types";
import { fallbackSummary, normalizeNistQuery, toPublicSummary } from "@/lib/text";

const VULDB_URL = "https://vuldb.com/?api";
const CVE_ID = /^CVE-\d{4}-\d{4,}$/;
// A consulta simples aceita no máximo três campos extras. Risco e CVE já vêm na resposta básica.
const FIELDS = ["software_vendor", "software_name", "countermeasure_remediationlevel"].join(",");

type RecordValue = Record<string, unknown>;

export type SourceHit = {
  ok: boolean;
  error?: string;
  vulnerabilities: Vuln[];
};

function isRecord(value: unknown): value is RecordValue {
  return typeof value === "object" && value !== null;
}

function asString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function unixDay(value: unknown): string {
  const number = typeof value === "number" ? value : Number(asString(value));
  if (!Number.isFinite(number) || number < 1_000_000_000) return "";
  return new Date(number * 1000).toISOString().slice(0, 10);
}

function severityFromName(name: string, score: number | null): Severity {
  const value = name.toLowerCase();
  if (value.includes("critical")) return "critical";
  if (value.includes("high")) return "high";
  if (value.includes("medium")) return "medium";
  if (value.includes("low")) return "low";
  if (score === null) return "unknown";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

function severityFromRisk(name: string, riskValue: unknown, score: number | null): Severity {
  const named = severityFromName(name, score);
  if (named !== "unknown") return named;
  const number = typeof riskValue === "number" ? riskValue : Number(asString(riskValue));
  if (!Number.isFinite(number)) return "unknown";
  if (number >= 4) return "critical";
  if (number >= 3) return "high";
  if (number >= 2) return "medium";
  if (number >= 1) return "low";
  return "unknown";
}

function scoreFrom(value: unknown): number | null {
  const number = typeof value === "number" ? value : Number(asString(value));
  return Number.isFinite(number) ? number : null;
}

function nameList(value: unknown): string {
  if (typeof value === "string") return value.trim();
  if (!Array.isArray(value)) return "";
  return value.map(asString).filter(Boolean).slice(0, 2).join(", ");
}

function remediationFromLevel(level: string) {
  const value = level.toLowerCase();
  if (!value || value.includes("not defined") || value.includes("unavailable")) return null;
  if (value.includes("workaround") || value.includes("mitigation")) {
    return remediationFor({ patch: false, mitigation: true, kev: false });
  }
  if (value.includes("fix") || value.includes("patch") || value.includes("upgrade")) {
    return remediationFor({ patch: true, mitigation: false, kev: false });
  }
  return null;
}

export function parseVuldbPayload(payload: unknown): { ok: boolean; error?: string; vulnerabilities: Vuln[] } {
  if (!isRecord(payload) || !isRecord(payload.response)) {
    return { ok: false, error: "O VulDB não respondeu.", vulnerabilities: [] };
  }
  const status = asString(payload.response.status);
  if (status === "204") return { ok: true, vulnerabilities: [] };
  if (status !== "200") {
    const message = asString(payload.response.error).toLowerCase();
    if (status === "401" || message.includes("key") || message.includes("api")) {
      return { ok: false, error: "O VulDB recusou a chave.", vulnerabilities: [] };
    }
    return { ok: false, error: "O VulDB não respondeu.", vulnerabilities: [] };
  }
  const result = Array.isArray(payload.result) ? payload.result : [];
  const vulnerabilities: Vuln[] = [];
  for (const entry of result) {
    if (!isRecord(entry) || !isRecord(entry.entry)) continue;
    const vuldbId = asString(entry.entry.id);
    const source = isRecord(entry.source) && isRecord(entry.source.cve) ? entry.source.cve : {};
    const cve = asString(source.id);
    const id = CVE_ID.test(cve) ? cve : vuldbId ? `VULDB-${vuldbId}` : "";
    if (!id) continue;
    const software = isRecord(entry.software) ? entry.software : {};
    const vendor = nameList(software.vendor) || "VulDB";
    const product = nameList(software.name) || "Produto não identificado";
    const vulnerability = isRecord(entry.vulnerability) ? entry.vulnerability : {};
    const risk = isRecord(vulnerability.risk) ? vulnerability.risk : {};
    const cvss3 = isRecord(vulnerability.cvss3) ? vulnerability.cvss3 : {};
    const nvd = isRecord(cvss3.nvd) ? cvss3.nvd : {};
    const vuldbScore = isRecord(cvss3.vuldb) ? cvss3.vuldb : {};
    const cvss = scoreFrom(nvd.basescore) ?? scoreFrom(vuldbScore.basescore);
    const cwe = asString(vulnerability.cwe);
    const countermeasure = isRecord(entry.countermeasure) ? entry.countermeasure : {};
    const published =
      unixDay(isRecord(entry.advisory) ? entry.advisory.date : "") ||
      unixDay(isRecord(entry.entry.timestamp) ? entry.entry.timestamp.create : "");
    const title = asString(entry.entry.title);
    vulnerabilities.push({
      id,
      name: toPublicSummary(title, `Registro VulDB ${id}`),
      summary: toPublicSummary(title, fallbackSummary({ id, vendor, product })),
      vendor,
      product,
      published,
      severity: severityFromRisk(asString(risk.name), risk.value, cvss),
      cvss,
      kev: false,
      ransomware: null,
      forensicTriage: false,
      dueDate: null,
      cwes: /^CWE-\d+$/.test(cwe) ? [cwe] : [],
      references: collectLinks([
        vuldbId ? `https://vuldb.com/?id.${vuldbId}` : "",
        CVE_ID.test(cve) ? `https://nvd.nist.gov/vuln/detail/${cve}` : "",
      ]),
      sources: ["vuldb"],
      remediation: remediationFromLevel(asString(countermeasure.remediationlevel)),
    });
  }
  return { ok: true, vulnerabilities };
}

async function queryVuldb(params: Record<string, string>): Promise<SourceHit> {
  const key = process.env.VULDB_API_KEY?.trim();
  if (!key) return { ok: false, error: "O VulDB precisa da chave VULDB_API_KEY.", vulnerabilities: [] };
  try {
    const response = await fetch(VULDB_URL, {
      method: "POST",
      signal: AbortSignal.timeout(15_000),
      headers: {
        accept: "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "user-agent": "ronda-plantao/0.1",
        "x-vuldb-apikey": key,
      },
      body: new URLSearchParams({ details: "0", fields: FIELDS, ...params }).toString(),
      cache: "no-store",
    });
    if (!response.ok) return { ok: false, error: "O VulDB não respondeu.", vulnerabilities: [] };
    const payload: unknown = await response.json();
    const report = isRecord(payload) && isRecord(payload.response) ? payload.response : {};
    console.log(`VulDB status ${asString(report.status) || "sem status"} itens ${String(report.items ?? "0")}`);
    return parseVuldbPayload(payload);
  } catch {
    return { ok: false, error: "O VulDB não respondeu.", vulnerabilities: [] };
  }
}

export async function searchVuldb(raw: string): Promise<SourceHit> {
  const query = normalizeNistQuery(raw);
  if (!query) return { ok: true, vulnerabilities: [] };
  const hit = await queryVuldb({ search: query });
  if (!hit.ok) return hit;
  const preferred = hit.vulnerabilities.filter((item) => item.severity !== "low");
  const selected = preferred.length > 0 ? preferred : hit.vulnerabilities;
  return {
    ok: true,
    vulnerabilities: selected.sort((a, b) => b.published.localeCompare(a.published)).slice(0, 12),
  };
}

export async function loadVuldbRecent(): Promise<{ items: Vuln[]; report: SourceReport }> {
  const hit = await queryVuldb({ recent: "100" });
  if (!hit.ok) {
    return { items: [], report: { id: "vuldb", label: "VulDB", ok: false, count: 0, error: hit.error } };
  }
  const items = hit.vulnerabilities
    .filter((item) => item.severity === "critical" || item.severity === "high")
    .sort((a, b) => b.published.localeCompare(a.published))
    .slice(0, 12);
  console.log(`VulDB lidos ${hit.vulnerabilities.length}, alta ou crítica ${items.length}`);
  return { items, report: { id: "vuldb", label: "VulDB", ok: true, count: items.length } };
}
