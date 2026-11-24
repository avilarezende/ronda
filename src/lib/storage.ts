"use client";

import { useCallback, useSyncExternalStore } from "react";
import { DEFAULT_ASSETS } from "@/lib/defaults";
import type { Asset, Criticality, TriageEntry, TriageStatus } from "@/lib/types";

export const ASSETS_KEY = "ronda.assets.v1";
export const TRIAGE_KEY = "ronda.triage.v1";

const STATUSES = new Set<TriageStatus>([
  "nova",
  "em-analise",
  "afeta",
  "nao-afeta",
  "mitigada",
  "risco-aceito",
]);

const CRITICALITIES = new Set<Criticality>(["essencial", "importante", "apoio"]);

export const STORAGE_WRITE_ERROR =
  "Não foi possível gravar neste navegador. O armazenamento pode estar cheio ou bloqueado.";

const STORAGE_READ_ERROR = "Não foi possível ler o que já está gravado neste navegador.";
const STORAGE_NOT_READY = "Os dados deste navegador ainda estão sendo lidos. Tente de novo em instantes.";

export type SaveResult = { ok: true } | { ok: false; error: string };

function cloneAsset(asset: Asset): Asset {
  return { ...asset, keywords: [...asset.keywords] };
}

function cloneDefaults(): Asset[] {
  return DEFAULT_ASSETS.map(cloneAsset);
}

function isAsset(value: unknown): value is Asset {
  if (!value || typeof value !== "object") return false;
  const asset = value as Partial<Asset>;
  return (
    typeof asset.id === "string" &&
    asset.id.length > 0 &&
    typeof asset.name === "string" &&
    Array.isArray(asset.keywords) &&
    asset.keywords.every((keyword) => typeof keyword === "string") &&
    typeof asset.criticality === "string" &&
    CRITICALITIES.has(asset.criticality) &&
    typeof asset.note === "string"
  );
}

function isTriage(value: unknown): value is TriageEntry {
  if (!value || typeof value !== "object") return false;
  const entry = value as Partial<TriageEntry>;
  return (
    typeof entry.status === "string" &&
    STATUSES.has(entry.status) &&
    typeof entry.note === "string" &&
    typeof entry.updatedAt === "string"
  );
}

/**
 * `null` or `""` means nothing was stored yet, so the examples are the starting point.
 * A stored array is the user's list, including an intentional empty one.
 */
export function readAssets(raw: string | null): Asset[] {
  if (raw === null || raw === "") return cloneDefaults();
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return cloneDefaults();
    return parsed.filter(isAsset);
  } catch {
    return cloneDefaults();
  }
}

export function readTriage(raw: string | null): Record<string, TriageEntry> {
  if (raw === null || raw === "") return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    return {};
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
  const entries: Record<string, TriageEntry> = {};
  for (const [id, value] of Object.entries(parsed)) {
    if (isTriage(value)) entries[id] = value;
  }
  return entries;
}

function browserStorage(): Storage | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

export function loadAssets(): Asset[] {
  const storage = browserStorage();
  if (!storage) return cloneDefaults();
  try {
    return readAssets(storage.getItem(ASSETS_KEY));
  } catch {
    return cloneDefaults();
  }
}

export function loadTriage(): Record<string, TriageEntry> {
  const storage = browserStorage();
  if (!storage) return {};
  try {
    return readTriage(storage.getItem(TRIAGE_KEY));
  } catch {
    return {};
  }
}

function emitStoreChange() {
  window.dispatchEvent(new Event("ronda-store"));
}

function writeRaw(key: string, value: unknown): SaveResult {
  const storage = browserStorage();
  if (!storage) return { ok: false, error: STORAGE_WRITE_ERROR };
  try {
    storage.setItem(key, JSON.stringify(value));
  } catch {
    return { ok: false, error: STORAGE_WRITE_ERROR };
  }
  try {
    emitStoreChange();
  } catch {
    // The value is already stored. Listeners are best-effort.
  }
  return { ok: true };
}

export function saveAssets(assets: Asset[]): SaveResult {
  return writeRaw(ASSETS_KEY, assets);
}

export function saveTriage(triage: Record<string, TriageEntry>): SaveResult {
  return writeRaw(TRIAGE_KEY, triage);
}

function readTriageForUpdate(): { ok: true; entries: Record<string, TriageEntry> } | { ok: false; error: string } {
  const storage = browserStorage();
  if (!storage) return { ok: false, error: STORAGE_READ_ERROR };
  try {
    const raw = storage.getItem(TRIAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as unknown;
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return { ok: false, error: "A triagem gravada neste navegador está ilegível." };
      }
    }
    return { ok: true, entries: readTriage(raw) };
  } catch {
    return { ok: false, error: STORAGE_READ_ERROR };
  }
}

export function saveTriageEntry(id: string, status: TriageStatus, note: string): SaveResult {
  if (!STATUSES.has(status) || id.trim().length === 0) {
    return { ok: false, error: "Essa triagem não é válida." };
  }
  const current = readTriageForUpdate();
  if (!current.ok) return current;
  return writeRaw(TRIAGE_KEY, {
    ...current.entries,
    [id]: { status, note, updatedAt: new Date().toISOString() },
  });
}

const STORAGE_NOT_READY_ERROR: SaveResult = { ok: false, error: STORAGE_NOT_READY };

function subscribe(onStoreChange: () => void) {
  window.addEventListener("ronda-store", onStoreChange);
  window.addEventListener("storage", onStoreChange);
  return () => {
    window.removeEventListener("ronda-store", onStoreChange);
    window.removeEventListener("storage", onStoreChange);
  };
}

function readKey(key: string): string {
  try {
    return window.localStorage.getItem(key) ?? "";
  } catch {
    return "";
  }
}

function assetsRawSnapshot() {
  return readKey(ASSETS_KEY);
}

function triageRawSnapshot() {
  return readKey(TRIAGE_KEY);
}

function serverRaw() {
  return "";
}

function clientReady() {
  return true;
}

function serverReady() {
  return false;
}

let assetCache: { raw: string; assets: Asset[] } | null = null;
let triageCache: { raw: string; triage: Record<string, TriageEntry> } | null = null;

function cachedAssets(raw: string): Asset[] {
  if (assetCache?.raw === raw) return assetCache.assets;
  const assets = readAssets(raw === "" ? null : raw);
  assetCache = { raw, assets };
  return assets;
}

function cachedTriage(raw: string): Record<string, TriageEntry> {
  if (triageCache?.raw === raw) return triageCache.triage;
  const triage = readTriage(raw === "" ? null : raw);
  triageCache = { raw, triage };
  return triage;
}

export function usePlantaoStore() {
  const ready = useSyncExternalStore(subscribe, clientReady, serverReady);
  const assetsRaw = useSyncExternalStore(subscribe, assetsRawSnapshot, serverRaw);
  const triageRaw = useSyncExternalStore(subscribe, triageRawSnapshot, serverRaw);
  const saveAssetList = useCallback((next: Asset[]) => (ready ? saveAssets(next) : STORAGE_NOT_READY_ERROR), [ready]);
  const saveEntry = useCallback(
    (id: string, status: TriageStatus, note: string) => (ready ? saveTriageEntry(id, status, note) : STORAGE_NOT_READY_ERROR),
    [ready],
  );

  return {
    assets: ready ? cachedAssets(assetsRaw) : [],
    triage: ready ? cachedTriage(triageRaw) : {},
    ready,
    saveAssets: saveAssetList,
    saveTriageEntry: saveEntry,
  };
}
