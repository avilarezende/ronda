import { dedupeLinks } from "@/lib/links";
import { preferRemediation } from "@/lib/remediation";
import type { Severity, Vuln } from "@/lib/types";

const GENERIC_PRODUCT = new Set(["Publicação NVD", "Produto não identificado", "Pacote não identificado"]);
const GENERIC_VENDOR = new Set(["Não identificado", "OSV.dev", "VulDB"]);

const SEVERITY_RANK: Record<Severity, number> = {
  unknown: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function mergeVuln(current: Vuln, incoming: Vuln): Vuln {
  const sources = [...new Set([...current.sources, ...incoming.sources])];
  const incomingVendor = GENERIC_VENDOR.has(incoming.vendor) ? current.vendor : incoming.vendor;
  return {
    ...current,
    name: current.name || incoming.name,
    summary: current.summary.length >= incoming.summary.length ? current.summary : incoming.summary,
    vendor: GENERIC_VENDOR.has(current.vendor) ? incomingVendor : current.vendor,
    product: GENERIC_PRODUCT.has(current.product) ? incoming.product : current.product,
    published: current.published || incoming.published,
    severity:
      SEVERITY_RANK[current.severity] >= SEVERITY_RANK[incoming.severity] ? current.severity : incoming.severity,
    cvss: current.cvss ?? incoming.cvss,
    kev: current.kev || incoming.kev,
    ransomware: current.ransomware === "Known" || incoming.ransomware === "Known" ? "Known" : current.ransomware ?? incoming.ransomware,
    forensicTriage: current.forensicTriage || incoming.forensicTriage,
    dueDate: current.dueDate ?? incoming.dueDate,
    cwes: current.cwes.length > 0 ? current.cwes : incoming.cwes,
    references: dedupeLinks([...current.references, ...incoming.references]),
    sources,
    remediation: preferRemediation(current.remediation, incoming.remediation),
  };
}
