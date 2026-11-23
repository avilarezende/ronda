import { collectLinks } from "@/lib/links";
import { remediationFor } from "@/lib/remediation";
import type { Severity, SourceReport, Vuln } from "@/lib/types";
import { cweName, fallbackSummary, normalizeNistQuery, toPublicSummary } from "@/lib/text";

const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const CVE_ID = /^CVE-\d{4}-\d{4,}$/;
const PATCH_TAGS = new Set(["Vendor Advisory", "Patch", "Release Notes"]);

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

async function fetchText(url: string): Promise<string> {
  const response = await fetch(url, {
    signal: AbortSignal.timeout(20_000),
    headers: {
      accept: "application/json",
      ...(typeof window === "undefined" ? { "user-agent": "ronda-plantao/0.1" } : {}),
    },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.text();
}

function nvdStamp(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, ".000");
}

function severityFromScore(score: number | null): Severity {
  if (score === null) return "unknown";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

function severityFromLabel(label: string, score: number | null): Severity {
  const value = label.toLowerCase();
  if (value === "critical") return "critical";
  if (value === "high") return "high";
  if (value === "medium") return "medium";
  if (value === "low") return "low";
  return severityFromScore(score);
}

function parseCpe(criteria: string): { vendor: string; product: string } | null {
  const parts = criteria.split(":");
  if (parts.length < 5) return null;
  const vendor = parts[3]?.replace(/_/g, " ");
  const product = parts[4]?.replace(/_/g, " ");
  if (!vendor || vendor === "*" || !product || product === "*") return null;
  return { vendor, product };
}

function productFromNvd(cve: RecordValue): { vendor: string; product: string } {
  const configurations = Array.isArray(cve.configurations) ? cve.configurations : [];
  for (const configuration of configurations) {
    if (!isRecord(configuration)) continue;
    const nodes = Array.isArray(configuration.nodes) ? configuration.nodes : [];
    for (const node of nodes) {
      if (!isRecord(node)) continue;
      const matches = Array.isArray(node.cpeMatch) ? node.cpeMatch : [];
      for (const match of matches) {
        if (!isRecord(match)) continue;
        const parsed = parseCpe(asString(match.criteria));
        if (parsed) return parsed;
      }
    }
  }
  return { vendor: "Não identificado", product: "Publicação NVD" };
}

function cvssFromNvd(cve: RecordValue): { score: number | null; severity: Severity } {
  const metrics = isRecord(cve.metrics) ? cve.metrics : {};
  const buckets = ["cvssMetricV31", "cvssMetricV40", "cvssMetricV30"];
  for (const bucket of buckets) {
    const list = Array.isArray(metrics[bucket]) ? metrics[bucket] : [];
    const first = list.find(isRecord);
    if (!first) continue;
    const data = isRecord(first.cvssData) ? first.cvssData : null;
    if (!data || typeof data.baseScore !== "number") continue;
    return {
      score: data.baseScore,
      severity: severityFromLabel(asString(data.baseSeverity), data.baseScore),
    };
  }
  return { score: null, severity: "unknown" };
}

function cwesFromNvd(cve: RecordValue): string[] {
  const weaknesses = Array.isArray(cve.weaknesses) ? cve.weaknesses : [];
  const ids = new Set<string>();
  for (const weakness of weaknesses) {
    if (!isRecord(weakness)) continue;
    const descriptions = Array.isArray(weakness.description) ? weakness.description : [];
    for (const description of descriptions) {
      if (!isRecord(description)) continue;
      const value = asString(description.value);
      if (/^CWE-\d+$/.test(value)) ids.add(value);
    }
  }
  return [...ids];
}

function nvdReferences(cve: RecordValue): { links: string[]; patch: boolean; mitigation: boolean } {
  const links: string[] = [];
  let patch = false;
  let mitigation = false;
  const references = Array.isArray(cve.references) ? cve.references : [];
  for (const reference of references) {
    if (!isRecord(reference)) continue;
    const tags = Array.isArray(reference.tags) ? reference.tags.map(asString) : [];
    const isPatch = tags.some((tag) => PATCH_TAGS.has(tag));
    const isMitigation = tags.includes("Mitigation");
    if (!isPatch && !isMitigation) continue;
    const href = asString(reference.url);
    const collected = collectLinks([href]);
    if (collected.length === 0) continue;
    links.push(collected[0].href);
    if (isPatch) patch = true;
    if (isMitigation) mitigation = true;
  }
  return { links, patch, mitigation };
}

export function parseNvd(payload: unknown): Vuln[] {
  if (!isRecord(payload) || !Array.isArray(payload.vulnerabilities)) return [];
  const items: Vuln[] = [];
  for (const entry of payload.vulnerabilities) {
    if (!isRecord(entry) || !isRecord(entry.cve)) continue;
    const cve = entry.cve;
    const id = asString(cve.id);
    if (!CVE_ID.test(id)) continue;
    const descriptions = Array.isArray(cve.descriptions) ? cve.descriptions : [];
    const english = descriptions.find((description) => isRecord(description) && description.lang === "en");
    const raw = isRecord(english) ? asString(english.value) : "";
    const { vendor, product } = productFromNvd(cve);
    const { score, severity } = cvssFromNvd(cve);
    const cwes = cwesFromNvd(cve);
    const references = nvdReferences(cve);
    const name = cwes[0] ? `${product} — ${cweName(cwes[0])}` : `${product} — vulnerabilidade publicada`;
    items.push({
      id,
      name,
      summary: toPublicSummary(raw, fallbackSummary({ id, vendor, product })),
      vendor,
      product,
      published: asString(cve.published).slice(0, 10),
      severity,
      cvss: score,
      kev: false,
      ransomware: null,
      forensicTriage: false,
      dueDate: null,
      cwes,
      references: collectLinks([`https://nvd.nist.gov/vuln/detail/${id}`, ...references.links]),
      sources: ["nvd"],
      remediation: remediationFor({ patch: references.patch, mitigation: references.mitigation, kev: false }),
    });
  }
  return items;
}

export async function loadRecentNvd(): Promise<{ items: Vuln[]; report: SourceReport }> {
  try {
    const end = new Date(Date.now() - 2 * 60 * 1000);
    const start = new Date(end.getTime() - 14 * 24 * 60 * 60 * 1000);
    const window = `pubStartDate=${nvdStamp(start)}&pubEndDate=${nvdStamp(end)}`;
    const headText = await fetchText(`${NVD_URL}?resultsPerPage=1&startIndex=0&${window}`);
    const head = JSON.parse(headText) as unknown;
    const total = isRecord(head) && typeof head.totalResults === "number" ? head.totalResults : 0;
    if (total === 0) return { items: [], report: { id: "nvd", label: "NIST NVD", ok: true, count: 0 } };
    const page = Math.min(80, total);
    const startIndex = Math.max(0, total - page);
    const pageText = await fetchText(`${NVD_URL}?resultsPerPage=${page}&startIndex=${startIndex}&${window}`);
    const recent = parseNvd(JSON.parse(pageText) as unknown)
      .filter((item) => item.severity === "critical" || item.severity === "high")
      .sort((a, b) => b.published.localeCompare(a.published))
      .slice(0, 30);
    return { items: recent, report: { id: "nvd", label: "NIST NVD", ok: true, count: recent.length } };
  } catch {
    return { items: [], report: { id: "nvd", label: "NIST NVD", ok: false, count: 0, error: "O NIST não respondeu." } };
  }
}

function pickNistHits(items: Vuln[]): Vuln[] {
  const ranked = [...items].sort((a, b) => b.published.localeCompare(a.published));
  const preferred = ranked.filter(
    (item) => item.severity === "critical" || item.severity === "high" || item.severity === "medium",
  );
  if (preferred.length >= 5) return preferred.slice(0, 15);
  return [...preferred, ...ranked.filter((item) => !preferred.includes(item))].slice(0, 8);
}

async function nvdSearchPage(params: string): Promise<{ total: number; items: Vuln[] }> {
  const text = await fetchText(`${NVD_URL}?${params}`);
  const payload = JSON.parse(text) as unknown;
  const total = isRecord(payload) && typeof payload.totalResults === "number" ? payload.totalResults : 0;
  return { total, items: parseNvd(payload) };
}

const nistCache = new Map<string, { expires: number; body: SourceHit }>();

export async function searchNist(raw: string): Promise<SourceHit> {
  const query = normalizeNistQuery(raw);
  if (!query) return { ok: true, vulnerabilities: [] };
  const key = query.toLowerCase();
  const cached = nistCache.get(key);
  if (cached && cached.expires > Date.now()) return cached.body;
  try {
    const cve = query.toUpperCase();
    const items = CVE_ID.test(cve)
      ? (await nvdSearchPage(`cveId=${encodeURIComponent(cve)}`)).items
      : await (async () => {
          const search = `keywordSearch=${encodeURIComponent(query)}`;
          const head = await nvdSearchPage(`resultsPerPage=1&startIndex=0&${search}`);
          if (head.total === 0) return [];
          const page = Math.min(30, head.total);
          const startIndex = Math.max(0, head.total - page);
          const tail = await nvdSearchPage(`resultsPerPage=${page}&startIndex=${startIndex}&${search}`);
          return pickNistHits(tail.items);
        })();
    const body: SourceHit = { ok: true, vulnerabilities: items };
    nistCache.set(key, { expires: Date.now() + 2 * 60 * 1000, body });
    if (nistCache.size > 40) {
      const oldest = nistCache.keys().next().value;
      if (oldest) nistCache.delete(oldest);
    }
    return body;
  } catch {
    return { ok: false, error: "O NIST não respondeu.", vulnerabilities: [] };
  }
}
