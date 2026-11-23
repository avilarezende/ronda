"use client";

import { useSyncExternalStore } from "react";
import { DEFAULT_ASSETS } from "@/lib/defaults";
import type { Asset, Criticality, TriageEntry, TriageStatus } from "@/lib/types";

const ASSETS_KEY = "ronda.assets.v1";
const TRIAGE_KEY = "ronda.triage.v1";

const STATUSES = new Set<TriageStatus>([
  "nova",
  "em-analise",
  "afeta",
  "nao-afeta",
  "mitigada",
  "risco-aceito",
]);

const CRITICALITIES = new Set<Criticality>(["essencial", "importante", "apoio"]);

function readJson(key: string): unknown {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(key);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function isAsset(value: unknown): value is Asset {
  if (!value || typeof value !== "object") return false;
  const asset = value as Partial<Asset>;
  return (
    typeof asset.id === "string" &&
    typeof asset.name === "string" &&
    Array.isArray(asset.keywords) &&
    asset.keywords.every((keyword) => typeof keyword === "string") &&
    typeof asset.criticality === "string" &&
    CRITICALITIES.has(asset.criticality) &&
    typeof asset.note === "string"
  );
}

export function loadAssets(): Asset[] {
  const parsed = readJson(ASSETS_KEY);
  if (!Array.isArray(parsed)) return DEFAULT_ASSETS;
  const assets = parsed.filter(isAsset);
  return assets.length > 0 ? assets : DEFAULT_ASSETS;
}

function emitStoreChange() {
  window.dispatchEvent(new Event("ronda-store"));
}

function subscribe(onStoreChange: () => void) {
  window.addEventListener("ronda-store", onStoreChange);
  window.addEventListener("storage", onStoreChange);
  return () => {
    window.removeEventListener("ronda-store", onStoreChange);
    window.removeEventListener("storage", onStoreChange);
  };
}

export function useAssets(): [Asset[], (assets: Asset[]) => void] {
  const raw = useSyncExternalStore(
    subscribe,
    () => window.localStorage.getItem(ASSETS_KEY) ?? "",
    () => "",
  );
  const assets = raw ? loadAssetsFromRaw(raw) : DEFAULT_ASSETS;
  return [assets, saveAssets];
}

function loadAssetsFromRaw(raw: string): Asset[] {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return DEFAULT_ASSETS;
    const assets = parsed.filter(isAsset);
    return assets.length > 0 ? assets : DEFAULT_ASSETS;
  } catch {
    return DEFAULT_ASSETS;
  }
}

export function saveAssets(assets: Asset[]) {
  window.localStorage.setItem(ASSETS_KEY, JSON.stringify(assets));
  emitStoreChange();
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

export function loadTriage(): Record<string, TriageEntry> {
  const parsed = readJson(TRIAGE_KEY);
  return triageFromParsed(parsed);
}

function triageFromParsed(parsed: unknown): Record<string, TriageEntry> {
  if (!parsed || typeof parsed !== "object") return {};
  const entries: Record<string, TriageEntry> = {};
  for (const [id, value] of Object.entries(parsed)) {
    if (isTriage(value)) entries[id] = value;
  }
  return entries;
}

export function useTriage(): [Record<string, TriageEntry>, (triage: Record<string, TriageEntry>) => void] {
  const raw = useSyncExternalStore(
    subscribe,
    () => window.localStorage.getItem(TRIAGE_KEY) ?? "",
    () => "",
  );
  const triage = raw
    ? triageFromParsed(safeParse(raw))
    : {};
  return [triage, saveTriage];
}

function safeParse(raw: string): unknown {
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return null;
  }
}

export function saveTriage(triage: Record<string, TriageEntry>) {
  window.localStorage.setItem(TRIAGE_KEY, JSON.stringify(triage));
  emitStoreChange();
}
