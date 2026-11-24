import assert from "node:assert/strict";
import test from "node:test";
import { DEFAULT_ASSETS } from "./defaults";
import {
  ASSETS_KEY,
  TRIAGE_KEY,
  loadAssets,
  loadTriage,
  readAssets,
  readTriage,
  saveAssets,
  saveTriage,
  saveTriageEntry,
} from "./storage";

function installStorage() {
  const store = new Map<string, string>();
  const events: string[] = [];
  const windowMock = {
    localStorage: {
      getItem(key: string) {
        return store.has(key) ? store.get(key)! : null;
      },
      setItem(key: string, value: string) {
        store.set(key, value);
      },
      removeItem(key: string) {
        store.delete(key);
      },
    },
    dispatchEvent(event: Event) {
      events.push(event.type);
      return true;
    },
  };
  Object.assign(globalThis, { window: windowMock });
  return { store, events };
}

test("missing asset list starts from the examples", () => {
  const assets = readAssets(null);
  assert.deepEqual(
    assets.map((asset) => asset.id),
    DEFAULT_ASSETS.map((asset) => asset.id),
  );
  assert.notEqual(assets, DEFAULT_ASSETS);
});

test("stored empty asset list does not restore the examples", () => {
  assert.deepEqual(readAssets("[]"), []);
  assert.deepEqual(readAssets(JSON.stringify([])), []);
});

test("stored assets keep an intentional removal and the chosen criticality", () => {
  const kept = DEFAULT_ASSETS.filter((asset) => asset.id !== "windows").map((asset) =>
    asset.id === "fortinet" ? { ...asset, criticality: "apoio" as const, note: "Só o laboratório" } : asset,
  );
  const read = readAssets(JSON.stringify(kept));
  assert.equal(read.some((asset) => asset.id === "windows"), false);
  assert.equal(read.find((asset) => asset.id === "fortinet")?.criticality, "apoio");
  assert.equal(read.find((asset) => asset.id === "fortinet")?.note, "Só o laboratório");
});

test("invalid asset entries are dropped and an empty result stays empty", () => {
  const raw = JSON.stringify([
    { id: "", name: "Sem id", keywords: ["abc"], criticality: "apoio", note: "" },
    { id: "ok", name: "Servidor", keywords: ["linux"], criticality: "essencial", note: "Sala" },
    { id: "ruim", name: "Criticidade", keywords: ["x"], criticality: "urgente", note: "" },
  ]);
  const read = readAssets(raw);
  assert.deepEqual(
    read.map((asset) => asset.id),
    ["ok"],
  );
  assert.deepEqual(readAssets(JSON.stringify([{ id: "x" }])), []);
});

test("saving an empty list and reading it back does not restore the examples", () => {
  const { store } = installStorage();
  const saved = saveAssets([]);
  assert.equal(saved.ok, true);
  assert.equal(store.get(ASSETS_KEY), "[]");
  assert.deepEqual(loadAssets(), []);
});

test("saving assets does not erase triage", () => {
  installStorage();
  assert.equal(
    saveTriage({
      "CVE-2026-1": { status: "afeta", note: "Laboratório", updatedAt: "2026-11-24T12:00:00.000Z" },
    }).ok,
    true,
  );
  assert.equal(saveAssets([]).ok, true);
  assert.equal(loadTriage()["CVE-2026-1"]?.note, "Laboratório");
  assert.equal(loadTriage()["CVE-2026-1"]?.status, "afeta");
});

test("a new triage entry keeps the ones already stored", () => {
  installStorage();
  saveTriage({
    "CVE-2026-1": { status: "em-analise", note: "Primeira", updatedAt: "2026-11-24T12:00:00.000Z" },
    "CVE-2026-2": { status: "nao-afeta", note: "Segunda", updatedAt: "2026-11-24T12:05:00.000Z" },
  });
  const saved = saveTriageEntry("CVE-2026-3", "mitigada", "Terceira, com a versão nova");
  assert.equal(saved.ok, true);
  const triage = loadTriage();
  assert.equal(triage["CVE-2026-1"]?.note, "Primeira");
  assert.equal(triage["CVE-2026-2"]?.status, "nao-afeta");
  assert.equal(triage["CVE-2026-3"]?.status, "mitigada");
  assert.equal(triage["CVE-2026-3"]?.note, "Terceira, com a versão nova");
});

test("unreadable triage is left untouched", () => {
  const { store } = installStorage();
  store.set(TRIAGE_KEY, "{");
  const saved = saveTriageEntry("CVE-2026-9", "afeta", "nota");
  assert.equal(saved.ok, false);
  assert.equal(store.get(TRIAGE_KEY), "{");
});

test("a failed write does not report success or drop the previous list", () => {
  const { store } = installStorage();
  saveAssets([
    { id: "lab", name: "Laboratório", keywords: ["openwrt"], criticality: "essencial", note: "" },
  ]);
  const storage = (globalThis as { window: { localStorage: Storage } }).window.localStorage;
  storage.setItem = () => {
    throw new Error("quota");
  };
  const saved = saveAssets([]);
  assert.equal(saved.ok, false);
  if (!saved.ok) assert.match(saved.error, /navegador/);
  assert.equal(loadAssets().length, 1);
  assert.equal(loadAssets()[0]?.name, "Laboratório");
  assert.equal(store.get(ASSETS_KEY)?.includes("Laboratório"), true);
});

test("triage notes round-trip and unknown statuses are ignored", () => {
  const raw = JSON.stringify({
    "CVE-2026-4": { status: "risco-aceito", note: "Aceito pelo plantão", updatedAt: "2026-11-24T15:00:00.000Z" },
    "CVE-2026-5": { status: "fechada", note: "não", updatedAt: "2026-11-24T15:00:00.000Z" },
  });
  const triage = readTriage(raw);
  assert.equal(Object.keys(triage).length, 1);
  assert.equal(triage["CVE-2026-4"]?.note, "Aceito pelo plantão");
  assert.deepEqual(readTriage(null), {});
});
