import type { ReferenceLink } from "@/lib/types";

const ALLOWED_HOSTS = new Set([
  "nvd.nist.gov",
  "cisa.gov",
  "www.cisa.gov",
  "cert.br",
  "www.cert.br",
  "cursos.cert.br",
  "cartilha.cert.br",
  "forum.cert.br",
  "osv.dev",
  "vuldb.com",
  "www.vuldb.com",
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

export function allowHref(href: string): boolean {
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
  const url = new URL(href);
  if (url.hostname === "nvd.nist.gov") return "NIST";
  if (url.hostname === "osv.dev") return "OSV.dev";
  if (url.hostname === "vuldb.com" || url.hostname === "www.vuldb.com") return "VulDB";
  if (url.hostname.endsWith("cisa.gov")) {
    if (url.pathname.includes("known-exploited")) return "Catálogo KEV";
    if (url.pathname.includes("/bod-")) return "Diretriz CISA";
    return "CISA";
  }
  if (url.hostname.endsWith("cert.br")) return "CERT.br";
  return "Fabricante";
}

function canonicalHref(href: string): string | null {
  try {
    const url = new URL(href);
    url.hash = "";
    url.hostname = url.hostname.toLowerCase();
    if (url.pathname.length > 1) url.pathname = url.pathname.replace(/\/+$/, "");
    return url.toString();
  } catch {
    return null;
  }
}

export function pushLink(links: ReferenceLink[], href: string) {
  const canonical = canonicalHref(href);
  if (!canonical || !allowHref(canonical)) return;
  if (links.some((link) => link.href === canonical)) return;
  links.push({ label: linkLabel(canonical), href: canonical });
}

export function collectLinks(hrefs: string[]): ReferenceLink[] {
  const links: ReferenceLink[] = [];
  for (const href of hrefs) pushLink(links, href);
  return links;
}

export function dedupeLinks(links: ReferenceLink[]): ReferenceLink[] {
  return collectLinks(links.map((link) => link.href));
}
