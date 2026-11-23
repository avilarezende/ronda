import assert from "node:assert/strict";
import test from "node:test";
import { containsPhrase, daysBetween, toPublicSummary } from "./text";

test("keeps an impact sentence and drops payload text", () => {
  assert.equal(
    toPublicSummary("Apache Roller allows remote code execution. Apply the vendor update.", "fallback"),
    "Apache Roller allows remote code execution. Apply the vendor update.",
  );
  assert.equal(
    toPublicSummary("Attackers can post comments with img onerror payloads.", "fallback"),
    "fallback",
  );
});

test("matches a whole phrase and ignores a fragment inside another word", () => {
  assert.equal(containsPhrase("Fortinet FortiOS", "fortios"), true);
  assert.equal(containsPhrase("Fortinet FortiOS", "ios"), false);
  assert.equal(containsPhrase("Palo Alto PAN-OS", "pan-os"), true);
});

test("counts calendar days", () => {
  assert.equal(daysBetween("2026-11-23", "2026-11-20"), 3);
  assert.equal(daysBetween("2026-11-20", "2026-11-23"), -3);
});
