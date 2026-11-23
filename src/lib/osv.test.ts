import assert from "node:assert/strict";
import test from "node:test";
import { parseOsvRecord } from "./osv";
import { parseVuldbPayload } from "./vuldb";

test("reads an OSV record as a package fix and drops exploit details", () => {
  const item = parseOsvRecord({
    id: "GHSA-example-example-example",
    summary: "Allocation of resources without limits.",
    details: "Run msfvenom and curl | bash to reproduce.",
    aliases: ["CVE-2024-3094"],
    published: "2024-03-29T12:00:00Z",
    affected: [
      {
        package: { ecosystem: "PyPI", name: "xz" },
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "5.6.2" }] }],
      },
    ],
    references: [
      { type: "ADVISORY", url: "https://osv.dev/vulnerability/GHSA-example-example-example" },
      { type: "WEB", url: "https://evil.example/poc" },
    ],
  });
  assert.ok(item);
  assert.equal(item.id, "CVE-2024-3094");
  assert.equal(item.product, "xz");
  assert.equal(item.vendor, "PyPI");
  assert.equal(item.remediation?.kind, "correcao");
  assert.equal(item.sources.includes("osv"), true);
  assert.equal(item.summary.includes("msfvenom"), false);
  assert.equal(item.references.some((link) => link.href.includes("evil.example")), false);
  assert.equal(item.references.some((link) => link.label === "OSV.dev"), true);
});

test("reads a basic VulDB entry and ignores exploit text in the title", () => {
  const parsed = parseVuldbPayload({
    response: { status: "200" },
    result: [
      {
        entry: {
          id: "42",
          title: "Cisco Secure ACS memory corruption",
          timestamp: { create: "1700000000" },
        },
        vulnerability: {
          risk: { name: "high" },
          cwe: "CWE-119",
          cvss3: { nvd: { basescore: "8.1" } },
        },
        software: { vendor: "Cisco", name: "Secure ACS" },
        countermeasure: { remediationlevel: "Official Fix" },
        source: { cve: { id: "CVE-2003-0210" } },
      },
      {
        entry: { id: "43", title: "env x='() { :;}; echo vulnerable' bash payload" },
        vulnerability: { risk: { name: "critical" } },
        source: { cve: { id: "CVE-2014-6271" } },
      },
    ],
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.vulnerabilities[0]?.vendor, "Cisco");
  assert.equal(parsed.vulnerabilities[0]?.severity, "high");
  assert.equal(parsed.vulnerabilities[0]?.cvss, 8.1);
  assert.equal(parsed.vulnerabilities[0]?.remediation?.kind, "correcao");
  assert.equal(parsed.vulnerabilities[0]?.references.some((link) => link.label === "VulDB"), true);
  assert.equal(parsed.vulnerabilities[1]?.summary.includes("vulnerable"), false);
});

test("reports a missing VulDB key without echoing it", () => {
  const parsed = parseVuldbPayload({
    response: { status: "401", error: "API key wrong format (missing)" },
  });
  assert.equal(parsed.ok, false);
  assert.equal(parsed.error, "O VulDB recusou a chave.");
  assert.equal(parsed.error?.includes("missing"), false);
});
