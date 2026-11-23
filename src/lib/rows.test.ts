import assert from "node:assert/strict";
import test from "node:test";
import { buildRows, filterRows } from "./rows";
import type { Vuln } from "./types";

function vuln(overrides: Partial<Vuln>): Vuln {
  return {
    id: "CVE-2026-2000",
    name: "Publicação NVD — vulnerabilidade publicada",
    summary: "A flaw in the server.",
    vendor: "Não identificado",
    product: "Publicação NVD",
    published: "2026-11-20",
    severity: "high",
    cvss: 8,
    kev: false,
    ransomware: null,
    forensicTriage: false,
    dueDate: null,
    cwes: [],
    references: [],
    sources: ["nvd"],
    remediation: null,
    ...overrides,
  };
}

test("keeps a search hit whose visible title does not repeat the query", () => {
  const hit = vuln({
    id: "CVE-2026-2001",
    summary: "The database component accepts a crafted request.",
  });
  const rows = buildRows([hit], [], {}, "2026-11-23");
  const hidden = filterRows(rows, "tudo", "postgresql");
  const shown = filterRows(rows, "tudo", "postgresql", new Set(["CVE-2026-2001"]));
  assert.equal(hidden.length, 0);
  assert.equal(shown.length, 1);
});

test("matches a feed item when the word is only in the summary", () => {
  const rows = buildRows(
    [vuln({ summary: "PostgreSQL before 16.1 allows a crafted query." })],
    [],
    {},
    "2026-11-23",
  );
  assert.equal(filterRows(rows, "tudo", "postgresql").length, 1);
});
