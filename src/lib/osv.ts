import { collectLinks } from "@/lib/links";
import { mergeVuln } from "@/lib/merge-vuln";
import { remediationFor } from "@/lib/remediation";
import type { Severity, SourceReport, Vuln } from "@/lib/types";
import { fallbackSummary, normalizeNistQuery, toPublicSummary } from "@/lib/text";

const OSV_URL = "https://api.osv.dev/v1";
const CVE_ID = /^CVE-\d{4}-\d{4,}$/;
const ECOSYSTEMS = ["npm", "PyPI", "Maven", "Go", "crates.io", "Packagist", "NuGet", "RubyGems"] as const;

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

function severityFromScore(score: number): Severity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

function severityFromLabel(label: string): Severity | null {
  const value = label.toLowerCase();
  if (value.includes("critical")) return "critical";
  if (value === "high") return "high";
  if (value === "moderate" || value === "medium") return "medium";
  if (value === "low") return "low";
  return null;
}

async function fetchJson(url: string, init?: RequestInit): Promise<{ status: number; body: unknown }> {
  const response = await fetch(url, {
    ...init,
    signal: AbortSignal.timeout(12_000),
    headers: {
      accept: "application/json",
      ...(typeof window === "undefined" ? { "user-agent": "ronda-plantao/0.1" } : {}),
      ...init?.headers,
    },
    cache: "no-store",
  });
  if (!response.body) return { status: response.status, body: null };
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let text = "";
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > 1_500_000) {
      await reader.cancel();
      return { status: response.status, body: { vulns: [] } };
    }
    text += decoder.decode(value, { stream: true });
  }
  text += decoder.decode();
  return { status: response.status, body: text ? (JSON.parse(text) as unknown) : null };
}

function aliasFromMessage(body: unknown): string | null {
  if (!isRecord(body)) return null;
  const message = asString(body.message);
  return message.match(/GHSA-[a-z0-9-]+|CVE-\d{4}-\d{4,}/i)?.[0] ?? null;
}

async function fetchOsvRecord(id: string, followAlias = true): Promise<RecordValue | null> {
  const { status, body } = await fetchJson(`${OSV_URL}/vulns/${encodeURIComponent(id)}`);
  if (status === 404) {
    if (!followAlias) return null;
    const alias = aliasFromMessage(body);
    if (!alias || alias.toLowerCase() === id.toLowerCase()) return null;
    return fetchOsvRecord(alias, false);
  }
  if (status !== 200 || !isRecord(body)) throw new Error(`OSV HTTP ${status}`);
  return body;
}

function packagesOf(record: RecordValue): Array<{ ecosystem: string; name: string }> {
  const affected = Array.isArray(record.affected) ? record.affected : [];
  const packages: Array<{ ecosystem: string; name: string }> = [];
  for (const entry of affected) {
    if (!isRecord(entry) || !isRecord(entry.package)) continue;
    const name = asString(entry.package.name);
    if (!name) continue;
    packages.push({ ecosystem: asString(entry.package.ecosystem), name });
    if (packages.length >= 3) break;
  }
  return packages;
}

function hasFix(record: RecordValue): boolean {
  const affected = Array.isArray(record.affected) ? record.affected : [];
  for (const entry of affected) {
    if (!isRecord(entry) || !Array.isArray(entry.ranges)) continue;
    for (const range of entry.ranges) {
      if (!isRecord(range) || !Array.isArray(range.events)) continue;
      for (const event of range.events) {
        if (isRecord(event) && asString(event.fixed)) return true;
      }
    }
  }
  return false;
}

function severityOf(record: RecordValue): { severity: Severity; cvss: number | null } {
  const specific = isRecord(record.database_specific) ? record.database_specific : {};
  const labeled = severityFromLabel(asString(specific.severity));
  const scores = Array.isArray(record.severity) ? record.severity : [];
  for (const score of scores) {
    if (!isRecord(score)) continue;
    const raw = asString(score.score);
    if (/^\d+(\.\d+)?$/.test(raw)) {
      const cvss = Number(raw);
      return { severity: labeled ?? severityFromScore(cvss), cvss };
    }
  }
  return { severity: labeled ?? "unknown", cvss: null };
}

export function parseOsvRecord(record: RecordValue): Vuln | null {
  const osvId = asString(record.id);
  if (!osvId) return null;
  const aliases = Array.isArray(record.aliases) ? record.aliases.map(asString) : [];
  const cve = [osvId, ...aliases].find((id) => CVE_ID.test(id)) ?? "";
  const id = cve || osvId;
  const packages = packagesOf(record);
  const vendor = packages[0]?.ecosystem || "OSV.dev";
  const product = packages[0]?.name || "Pacote não identificado";
  const cited = packages.map((pkg) => (pkg.ecosystem ? `${pkg.ecosystem} ${pkg.name}` : pkg.name)).join(", ");
  const base = toPublicSummary(asString(record.summary), fallbackSummary({ id, vendor, product }));
  const summary = cited && !base.includes(packages[0]?.name ?? "") ? `${base} O OSV.dev cita ${cited}.` : base;
  const { severity, cvss } = severityOf(record);
  const advisoryLinks = Array.isArray(record.references) ? record.references : [];
  const hrefs = [`https://osv.dev/vulnerability/${encodeURIComponent(osvId)}`];
  if (cve) hrefs.push(`https://nvd.nist.gov/vuln/detail/${cve}`);
  for (const reference of advisoryLinks) {
    if (!isRecord(reference)) continue;
    const type = asString(reference.type);
    if (type !== "ADVISORY" && type !== "FIX") continue;
    hrefs.push(asString(reference.url));
  }
  return {
    id,
    name: product === "Pacote não identificado" ? `Registro ${osvId}` : `${product} — registro OSV.dev`,
    summary,
    vendor,
    product,
    published: (asString(record.published) || asString(record.modified)).slice(0, 10),
    severity,
    cvss,
    kev: false,
    ransomware: null,
    forensicTriage: false,
    dueDate: null,
    cwes: [],
    references: collectLinks(hrefs),
    sources: ["osv"],
    remediation: remediationFor({ patch: hasFix(record), mitigation: false, kev: false }),
  };
}

function pickRecent(items: Vuln[], limit: number): Vuln[] {
  const ranked = [...items].sort((a, b) => b.published.localeCompare(a.published));
  const preferred = ranked.filter(
    (item) => item.severity === "critical" || item.severity === "high" || item.severity === "medium",
  );
  const selected = preferred.length >= 5 ? preferred : ranked;
  const seen = new Set<string>();
  const result: Vuln[] = [];
  for (const item of selected) {
    if (seen.has(item.id)) continue;
    seen.add(item.id);
    result.push(item);
    if (result.length >= limit) break;
  }
  return result;
}

export async function searchOsv(raw: string): Promise<SourceHit> {
  const query = normalizeNistQuery(raw);
  if (!query) return { ok: true, vulnerabilities: [] };
  try {
    if (CVE_ID.test(query.toUpperCase())) {
      const record = await fetchOsvRecord(query.toUpperCase());
      const item = record ? parseOsvRecord(record) : null;
      return { ok: true, vulnerabilities: item ? [item] : [] };
    }
    const pages = await Promise.all(
      ECOSYSTEMS.map(async (ecosystem) => {
        try {
          const { status, body } = await fetchJson(`${OSV_URL}/query`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ package: { name: query, ecosystem } }),
          });
          if (status !== 200 || !isRecord(body) || !Array.isArray(body.vulns)) return [];
          return body.vulns.filter(isRecord).slice(0, 40).flatMap((record) => {
            const item = parseOsvRecord(record);
            return item ? [item] : [];
          });
        } catch {
          return [];
        }
      }),
    );
    return { ok: true, vulnerabilities: pickRecent(pages.flat(), 12) };
  } catch {
    return { ok: false, error: "O OSV.dev não respondeu.", vulnerabilities: [] };
  }
}

export async function annotateWithOsv(items: Vuln[]): Promise<{ items: Vuln[]; report: SourceReport }> {
  const targets = [...items].sort((a, b) => b.published.localeCompare(a.published)).filter((item) => CVE_ID.test(item.id)).slice(0, 24);
  const annotated = new Map(items.map((item) => [item.id, item]));
  let found = 0;
  let failed = 0;
  let cursor = 0;
  async function worker() {
    while (cursor < targets.length) {
      const item = targets[cursor];
      cursor += 1;
      try {
        const record = await fetchOsvRecord(item.id);
        if (!record) continue;
        const parsed = parseOsvRecord(record);
        if (!parsed) continue;
        found += 1;
        const current = annotated.get(item.id) ?? item;
        annotated.set(item.id, mergeVuln(current, parsed));
      } catch {
        failed += 1;
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(6, targets.length) }, () => worker()));
  const report: SourceReport =
    failed === targets.length && targets.length > 0
      ? { id: "osv", label: "OSV.dev", ok: false, count: 0, error: "O OSV.dev não respondeu." }
      : { id: "osv", label: "OSV.dev", ok: true, count: found };
  return { items: [...annotated.values()], report };
}
