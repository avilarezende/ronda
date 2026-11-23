import type { FeedResponse, Notice, ReferenceLink, Severity, SourceReport, Vuln } from "@/lib/types";
import { cweName, fallbackSummary, fortalezaToday, stripHtml, toPublicSummary } from "@/lib/text";

const CISA_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const CERT_URL = "https://cert.br/rss/";
const USER_AGENT = "ronda-plantao/0.1";
const TTL_MS = 10 * 60 * 1000;
const CVE_ID = /^CVE-\d{4}-\d{4,}$/;

const ALLOWED_HOSTS = new Set([
  "nvd.nist.gov",
  "cisa.gov",
  "www.cisa.gov",
  "cert.br",
  "www.cert.br",
  "cursos.cert.br",
  "cartilha.cert.br",
  "forum.cert.br",
  "lists.apache.org",
  "msrc.microsoft.com",
  "www.microsoft.com",
  "support.microsoft.com",
  "sec.cloudapps.cisco.com",
  "tools.cisco.com",
  "www.fortiguard.com",
  "fortiguard.fortinet.com",
  "www.fortinet.com",
  "security.paloaltonetworks.com",
  "access.redhat.com",
  "ubuntu.com",
  "www.oracle.com",
  "support.broadcom.com",
  "www.vmware.com",
  "kb.vmware.com",
  "helpx.adobe.com",
  "www.adobe.com",
  "chromereleases.googleblog.com",
  "www.debian.org",
  "security-tracker.debian.org",
  "alas.aws.amazon.com",
]);

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
    headers: { "user-agent": USER_AGENT, accept },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.text();
}

function nvdStamp(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, ".000");
}

function allowHref(href: string): boolean {
  try {
    const url = new URL(href);
    if (url.protocol !== "https:") return false;
    if (url.hostname === "github.com" || url.hostname === "www.github.com") {
      return url.pathname.startsWith("/advisories/");
    }
    return ALLOWED_HOSTS.has(url.hostname);
  } catch {
    return false;
  }
}

function linkLabel(href: string): string {
  const host = new URL(href).hostname;
  if (host === "nvd.nist.gov") return "NVD";
  if (host.endsWith("cisa.gov")) return "CISA";
  if (host.endsWith("cert.br")) return "CERT.br";
  return "Fabricante";
}

function pushLink(links: ReferenceLink[], href: string) {
  if (!allowHref(href)) return;
  if (links.some((link) => link.href === href)) return;
  links.push({ label: linkLabel(href), href });
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

function nvdReferences(cve: RecordValue): ReferenceLink[] {
  const links: ReferenceLink[] = [];
  const references = Array.isArray(cve.references) ? cve.references : [];
  for (const reference of references) {
    if (!isRecord(reference)) continue;
    const tags = Array.isArray(reference.tags) ? reference.tags.map(asString) : [];
    const useful = tags.some((tag) =>
      ["Vendor Advisory", "Patch", "Mitigation", "Release Notes"].includes(tag),
    );
    if (!useful && tags.length > 0) continue;
    if (tags.length === 0) continue;
    pushLink(links, asString(reference.url));
  }
  return links;
}

function parseNvd(payload: unknown): Vuln[] {
  if (!isRecord(payload) || !Array.isArray(payload.vulnerabilities)) return [];
  const items: Vuln[] = [];
  for (const entry of payload.vulnerabilities) {
    if (!isRecord(entry) || !isRecord(entry.cve)) continue;
    const cve = entry.cve;
    const id = asString(cve.id);
    if (!CVE_ID.test(id)) continue;
    const descriptions = Array.isArray(cve.descriptions) ? cve.descriptions : [];
    const english = descriptions.find(
      (description) => isRecord(description) && description.lang === "en",
    );
    const raw = isRecord(english) ? asString(english.value) : "";
    const { vendor, product } = productFromNvd(cve);
    const { score, severity } = cvssFromNvd(cve);
    const cwes = cwesFromNvd(cve);
    const name = cwes[0]
      ? `${product} — ${cweName(cwes[0])}`
      : `${product} — vulnerabilidade publicada`;
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
      references: [
        { label: "NVD", href: `https://nvd.nist.gov/vuln/detail/${id}` },
        ...nvdReferences(cve),
      ],
      sources: ["nvd"],
    });
  }
  return items;
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
    const cwes = Array.isArray(entry.cwes)
      ? entry.cwes.map(asString).filter((cwe) => /^CWE-\d+$/.test(cwe))
      : [];
    items.push({
      id,
      name: asString(entry.vulnerabilityName) || `${product} — vulnerabilidade no KEV`,
      summary: toPublicSummary(
        asString(entry.shortDescription),
        fallbackSummary({ id, vendor, product }),
      ),
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
      references: [
        { label: "NVD", href: `https://nvd.nist.gov/vuln/detail/${id}` },
        {
          label: "CISA",
          href: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${id}`,
        },
        ...noteLinks(asString(entry.notes)),
      ],
      sources: ["cisa-kev"],
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
    });
  }
  return [...byId.values()].sort((a, b) => {
    if (a.kev !== b.kev) return a.kev ? -1 : 1;
    return b.published.localeCompare(a.published);
  });
}

function dedupeLinks(links: ReferenceLink[]): ReferenceLink[] {
  const seen = new Set<string>();
  return links.filter((link) => {
    if (seen.has(link.href)) return false;
    seen.add(link.href);
    return true;
  });
}

async function loadKev(today: string): Promise<{ items: Vuln[]; report: SourceReport }> {
  try {
    const text = await fetchText(CISA_URL, 15_000, "application/json");
    const items = parseKev(JSON.parse(text) as unknown, today);
    return {
      items,
      report: { id: "cisa-kev", label: "CISA KEV", ok: true, count: items.length },
    };
  } catch {
    return {
      items: [],
      report: {
        id: "cisa-kev",
        label: "CISA KEV",
        ok: false,
        count: 0,
        error: "O catálogo KEV não respondeu.",
      },
    };
  }
}

async function loadNvd(): Promise<{ items: Vuln[]; report: SourceReport }> {
  try {
    const end = new Date(Date.now() - 2 * 60 * 1000);
    const start = new Date(end.getTime() - 14 * 24 * 60 * 60 * 1000);
    const window = `pubStartDate=${nvdStamp(start)}&pubEndDate=${nvdStamp(end)}`;
    const headText = await fetchText(`${NVD_URL}?resultsPerPage=1&startIndex=0&${window}`, 20_000, "application/json");
    const head = JSON.parse(headText) as unknown;
    const total = isRecord(head) && typeof head.totalResults === "number" ? head.totalResults : 0;
    if (total === 0) {
      return { items: [], report: { id: "nvd", label: "NVD", ok: true, count: 0 } };
    }
    const page = Math.min(80, total);
    const startIndex = Math.max(0, total - page);
    const pageText = await fetchText(
      `${NVD_URL}?resultsPerPage=${page}&startIndex=${startIndex}&${window}`,
      20_000,
      "application/json",
    );
    const recent = parseNvd(JSON.parse(pageText) as unknown)
      .filter((item) => item.severity === "critical" || item.severity === "high")
      .sort((a, b) => b.published.localeCompare(a.published))
      .slice(0, 30);
    return {
      items: recent,
      report: { id: "nvd", label: "NVD", ok: true, count: recent.length },
    };
  } catch {
    return {
      items: [],
      report: {
        id: "nvd",
        label: "NVD",
        ok: false,
        count: 0,
        error: "A NVD não respondeu.",
      },
    };
  }
}

async function loadCert(): Promise<{ notices: Notice[]; report: SourceReport }> {
  try {
    const xml = await fetchText(CERT_URL, 12_000, "application/rss+xml, text/xml");
    const notices = parseRss(xml);
    return {
      notices,
      report: { id: "certbr", label: "CERT.br", ok: true, count: notices.length },
    };
  } catch {
    return {
      notices: [],
      report: {
        id: "certbr",
        label: "CERT.br",
        ok: false,
        count: 0,
        error: "O feed do CERT.br não respondeu.",
      },
    };
  }
}

async function collect(): Promise<FeedResponse> {
  const today = fortalezaToday();
  const [kev, nvd, cert] = await Promise.all([loadKev(today), loadNvd(), loadCert()]);
  return {
    fetchedAt: new Date().toISOString(),
    today,
    sources: [kev.report, nvd.report, cert.report],
    vulnerabilities: merge(kev.items, nvd.items),
    notices: cert.notices,
  };
}

export async function loadFeed(force = false): Promise<FeedResponse> {
  const now = Date.now();
  if (cache && cache.expires > now && (!force || now - cache.fetchedAt < 60_000)) return cache.body;
  const body = await collect();
  const coreDown = body.sources.filter((source) => source.id !== "certbr").every((source) => !source.ok);
  cache = { expires: now + (coreDown ? 20_000 : TTL_MS), fetchedAt: now, body };
  return body;
}

export function clearFeedCache() {
  cache = null;
}
