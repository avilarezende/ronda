import { collectLinks, dedupeLinks, pushLink } from "@/lib/links";
import { mergeVuln } from "@/lib/merge-vuln";
import { loadRecentNvd } from "@/lib/nist";
import { annotateWithOsv } from "@/lib/osv";
import { preferRemediation, remediationFor } from "@/lib/remediation";
import { nextUpdate } from "@/lib/schedule";
import type { FeedResponse, Notice, ReferenceLink, SourceReport, Vuln } from "@/lib/types";
import { fallbackSummary, fortalezaToday, stripHtml, toPublicSummary } from "@/lib/text";
import { loadVuldbRecent } from "@/lib/vuldb";

const CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const CERT_URL = "https://cert.br/rss/";
const CVE_ID = /^CVE-\d{4}-\d{4,}$/;

type CacheEntry = { expires: number; fetchedAt: number; body: FeedResponse };
let cache: CacheEntry | null = null;

type RecordValue = Record<string, unknown>;

function isRecord(value: unknown): value is RecordValue {
  return typeof value === "object" && value !== null;
}

function asString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

async function fetchText(url: string, timeoutMs: number, accept: string): Promise<string> {
  const response = await fetch(url, {
    signal: AbortSignal.timeout(timeoutMs),
    headers: {
      accept,
      ...(typeof window === "undefined" ? { "user-agent": "ronda-plantao/0.1" } : {}),
    },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.text();
}

function noteLinks(notes: string): ReferenceLink[] {
  const links: ReferenceLink[] = [];
  for (const match of notes.matchAll(/https:\/\/[^\s;]+/g)) {
    pushLink(links, match[0].replace(/[),.;]+$/, ""));
  }
  return links;
}

function parseKev(payload: unknown, today: string): Vuln[] {
  if (!isRecord(payload) || !Array.isArray(payload.vulnerabilities)) return [];
  const cutoff = new Date(`${today}T00:00:00Z`);
  cutoff.setUTCDate(cutoff.getUTCDate() - 120);
  const cutoffIso = cutoff.toISOString().slice(0, 10);
  const items: Vuln[] = [];
  for (const entry of payload.vulnerabilities) {
    if (!isRecord(entry)) continue;
    const id = asString(entry.cveID);
    const published = asString(entry.dateAdded);
    if (!CVE_ID.test(id) || published < cutoffIso) continue;
    const vendor = asString(entry.vendorProject) || "Não identificado";
    const product = asString(entry.product) || "Produto não identificado";
    const ransomware = asString(entry.knownRansomwareCampaignUse);
    const cwes = Array.isArray(entry.cwes) ? entry.cwes.map(asString).filter((cwe) => /^CWE-\d+$/.test(cwe)) : [];
    const notes = noteLinks(asString(entry.notes));
    const patch = notes.some((link) => link.label === "Fabricante");
    items.push({
      id,
      name: asString(entry.vulnerabilityName) || `${product} — vulnerabilidade no KEV`,
      summary: toPublicSummary(asString(entry.shortDescription), fallbackSummary({ id, vendor, product })),
      vendor,
      product,
      published,
      severity: ransomware === "Known" ? "critical" : "high",
      cvss: null,
      kev: true,
      ransomware: ransomware === "Known" ? "Known" : "Unknown",
      forensicTriage: asString(entry.forensicTriage) === "Yes",
      dueDate: asString(entry.dueDate) || null,
      cwes,
      references: collectLinks([
        `https://nvd.nist.gov/vuln/detail/${id}`,
        `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${id}`,
        ...notes.map((link) => link.href),
      ]),
      sources: ["cisa-kev"],
      remediation: remediationFor({ patch, mitigation: !patch, kev: true }),
    });
  }
  return items.sort((a, b) => b.published.localeCompare(a.published)).slice(0, 160);
}

function parseRss(xml: string): Notice[] {
  const notices: Notice[] = [];
  for (const chunk of xml.split(/<item\b/i).slice(1, 6)) {
    const title = stripHtml(tag(chunk, "title"));
    const href = tag(chunk, "link").trim();
    const id = stripHtml(tag(chunk, "guid")) || href;
    const published = rssDate(tag(chunk, "pubDate"));
    const summary = stripHtml(tag(chunk, "description")).slice(0, 280);
    if (!title || !href.startsWith("https://")) continue;
    notices.push({ id, title, summary, published, href });
  }
  return notices;
}

function tag(chunk: string, name: string): string {
  const match = chunk.match(new RegExp(`<${name}[^>]*>([\\s\\S]*?)</${name}>`, "i"));
  return match?.[1]?.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1").trim() ?? "";
}

function rssDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toISOString().slice(0, 10);
}

function merge(kev: Vuln[], nvd: Vuln[]): Vuln[] {
  const byId = new Map<string, Vuln>();
  for (const item of nvd) {
    if (item.severity !== "critical" && item.severity !== "high") continue;
    byId.set(item.id, item);
  }
  for (const item of kev) {
    const existing = byId.get(item.id);
    if (!existing) {
      byId.set(item.id, item);
      continue;
    }
    byId.set(item.id, {
      ...item,
      cvss: existing.cvss,
      severity: existing.cvss !== null ? existing.severity : item.severity,
      summary: item.summary || existing.summary,
      cwes: item.cwes.length > 0 ? item.cwes : existing.cwes,
      references: dedupeLinks([...item.references, ...existing.references]),
      sources: ["cisa-kev", "nvd"],
      remediation: preferRemediation(item.remediation, existing.remediation),
    });
  }
  return [...byId.values()].sort((a, b) => {
    if (a.kev !== b.kev) return a.kev ? -1 : 1;
    return b.published.localeCompare(a.published);
  });
}

function fold(items: Vuln[], extra: Vuln[]): Vuln[] {
  const byId = new Map(items.map((item) => [item.id, item]));
  for (const item of extra) {
    const existing = byId.get(item.id);
    if (!existing) {
      if (item.severity === "critical" || item.severity === "high") byId.set(item.id, item);
      continue;
    }
    byId.set(item.id, mergeVuln(existing, item));
  }
  return [...byId.values()].sort((a, b) => {
    if (a.kev !== b.kev) return a.kev ? -1 : 1;
    return b.published.localeCompare(a.published);
  });
}

async function loadKev(today: string): Promise<{ items: Vuln[]; report: SourceReport }> {
  try {
    const text = await fetchText(CISA_URL, 15_000, "application/json");
    const items = parseKev(JSON.parse(text) as unknown, today);
    return { items, report: { id: "cisa-kev", label: "CISA KEV", ok: true, count: items.length } };
  } catch {
    return {
      items: [],
      report: { id: "cisa-kev", label: "CISA KEV", ok: false, count: 0, error: "O catálogo KEV não respondeu." },
    };
  }
}

async function loadCert(): Promise<{ notices: Notice[]; report: SourceReport }> {
  try {
    const xml = await fetchText(CERT_URL, 12_000, "application/rss+xml, text/xml");
    const notices = parseRss(xml);
    return { notices, report: { id: "certbr", label: "CERT.br", ok: true, count: notices.length } };
  } catch {
    return {
      notices: [],
      report: { id: "certbr", label: "CERT.br", ok: false, count: 0, error: "O feed do CERT.br não respondeu." },
    };
  }
}

async function collect(): Promise<FeedResponse> {
  const today = fortalezaToday();
  const [kev, nvd, cert] = await Promise.all([loadKev(today), loadRecentNvd(), loadCert()]);
  const base = merge(kev.items, nvd.items);
  const [osv, vuldb] = await Promise.all([annotateWithOsv(base), loadVuldbRecent()]);
  return {
    fetchedAt: new Date().toISOString(),
    nextUpdate: nextUpdate(new Date()).toISOString(),
    today,
    sources: [kev.report, nvd.report, osv.report, vuldb.report, cert.report],
    vulnerabilities: fold(osv.items, vuldb.items),
    notices: cert.notices,
  };
}

export async function loadFeed(force = false): Promise<FeedResponse> {
  const now = Date.now();
  if (cache && cache.expires > now && (!force || now - cache.fetchedAt < 60_000)) return cache.body;
  const body = await collect();
  const coreDown = body.sources
    .filter((source) => source.id === "cisa-kev" || source.id === "nvd")
    .every((source) => !source.ok);
  const expires = coreDown ? now + 20_000 : Date.parse(body.nextUpdate);
  cache = { expires, fetchedAt: now, body };
  return body;
}

export function clearFeedCache() {
  cache = null;
}
