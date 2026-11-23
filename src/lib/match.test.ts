import assert from "node:assert/strict";
import test from "node:test";
import { assess, defensiveAction } from "./match";
import type { Asset, Vuln } from "./types";

const forti: Asset = {
  id: "forti",
  name: "Fortinet",
  keywords: ["fortios", "fortigate"],
  criticality: "essencial",
  note: "",
};

function vuln(overrides: Partial<Vuln> = {}): Vuln {
  return {
    id: "CVE-2026-1000",
    name: "FortiOS authentication bypass",
    summary: "FortiOS allows an unauthenticated request on the management interface.",
    vendor: "Fortinet",
    product: "FortiOS",
    published: "2026-11-20",
    severity: "critical",
    cvss: 9.8,
    kev: true,
    ransomware: "Known",
    forensicTriage: false,
    dueDate: "2026-11-22",
    cwes: ["CWE-287"],
    references: [],
    sources: ["cisa-kev"],
    ...overrides,
  };
}

test("ranks an essential KEV match as urgent", () => {
  const match = assess(vuln(), [forti], "2026-11-23");
  assert.equal(match.priority, "urgente");
  assert.equal(match.assets[0]?.name, "Fortinet");
  assert.ok(match.reasons.some((reason) => reason.includes("essencial")));
});

test("does not match a keyword that is only a fragment", () => {
  const match = assess(vuln(), [{ ...forti, keywords: ["ios"] }], "2026-11-23");
  assert.equal(match.assets.length, 0);
  assert.equal(
    match.reasons.some((reason) => reason.includes("Fortinet")),
    false,
  );
});

test("keeps the recommended action on patching", () => {
  const action = defensiveAction(vuln(), true);
  assert.match(action, /atualização publicada pelo fabricante/);
  assert.doesNotMatch(action, /payload|exploit|msfvenom/i);
});
