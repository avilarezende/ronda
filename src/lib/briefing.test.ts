import assert from "node:assert/strict";
import test from "node:test";
import { writeBriefing } from "./briefing";

test("writes a quiet morning when nothing new matches", () => {
  const text = writeBriefing({
    kevRecent: 0,
    matched: 0,
    matchedEssential: 0,
    openTriage: 0,
    overdue: 0,
    top: null,
  });
  assert.match(text, /não recebeu entradas novas/);
  assert.match(text, /Nenhuma vulnerabilidade/);
  assert.match(text, /fila visível está triada/);
});

test("names the first item and an overdue essential match", () => {
  const text = writeBriefing({
    kevRecent: 2,
    matched: 1,
    matchedEssential: 1,
    openTriage: 4,
    overdue: 1,
    top: { id: "CVE-2026-1000", vendor: "Fortinet", product: "FortiOS" },
  });
  assert.match(text, /2 entradas/);
  assert.match(text, /um deles em ativo essencial/);
  assert.match(text, /passou do prazo/);
  assert.match(text, /CVE-2026-1000, Fortinet FortiOS/);
});
