"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { AssetsView } from "@/components/assets-view";
import { BriefingView } from "@/components/briefing-view";
import { FixesView } from "@/components/fixes-view";
import { QueueView } from "@/components/queue-view";
import { SourcesView } from "@/components/sources-view";
import { Button } from "@/components/ui/button";
import { VulnSheet } from "@/components/vuln-sheet";
import { searchPublic } from "@/lib/public-search";
import { buildRows, describePlantao, filterRows, type QueueFilter } from "@/lib/rows";
import { useAssets, useTriage } from "@/lib/storage";
import { formatUpdateHour } from "@/lib/schedule";
import { formatLongDay } from "@/lib/text";
import type { Asset, FeedResponse, TriageStatus, Vuln } from "@/lib/types";

type View = "briefing" | "fila" | "correcoes" | "ativos" | "fontes";

const PUBLISHED = process.env.NEXT_PUBLIC_STATIC === "1";
const BASE_PATH = (process.env.NEXT_PUBLIC_BASE_PATH ?? "").replace(/\/$/, "");

const VIEWS: Array<{ id: View; label: string }> = [
  { id: "briefing", label: "Briefing" },
  { id: "fila", label: "Fila" },
  { id: "correcoes", label: "Correções" },
  { id: "ativos", label: "Ativos" },
  { id: "fontes", label: "Fontes" },
];

export function Desk() {
  const [view, setView] = useState<View>("briefing");
  const [feed, setFeed] = useState<FeedResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [assets, setAssets] = useAssets();
  const [triage, setTriage] = useTriage();
  const [filter, setFilter] = useState<QueueFilter>("olhar");
  const [query, setQuery] = useState("");
  const [nist, setNist] = useState<Vuln[]>([]);
  const [nistNote, setNistNote] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setFeed(await requestFeed(true));
    } catch {
      setError("Não foi possível consultar as fontes agora.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    requestFeed(false, controller.signal)
      .then((body) => {
        if (!active) return;
        setFeed(body);
        setError(null);
      })
      .catch((reason: unknown) => {
        if (!active || (reason instanceof DOMException && reason.name === "AbortError")) return;
        setError("Não foi possível consultar as fontes agora.");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, []);

  useEffect(() => {
    const q = query.trim();
    let active = true;
    const timer = window.setTimeout(() => {
      if (q.length < 3) {
        setNist([]);
        setNistNote(null);
        return;
      }
      setNistNote("Consultando NIST, OSV.dev e VulDB…");
      const request = PUBLISHED
        ? searchPublic(q)
        : fetch(`/api/search?q=${encodeURIComponent(q)}`, { cache: "no-store" }).then(async (response) => {
            if (!response.ok) throw new Error("search");
            return (await response.json()) as { ok: boolean; error?: string; note?: string; vulnerabilities?: Vuln[] };
          });
      request
        .then((body) => {
          if (!active) return;
          setNist(body.vulnerabilities ?? []);
          if (!body.ok) {
            setNistNote(body.note || body.error || "A busca não respondeu.");
            return;
          }
          setNistNote(body.note ?? "");
        })
        .catch(() => {
          if (!active) return;
          setNist([]);
          setNistNote("A busca não respondeu.");
        });
    }, q.length < 3 ? 0 : 450);
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [query]);

  useEffect(() => {
    if (!feed?.nextUpdate) return;
    const delay = Date.parse(feed.nextUpdate) - Date.now();
    const timer = window.setTimeout(() => {
      void refresh();
    }, Math.max(delay, 1_000));
    return () => window.clearTimeout(timer);
  }, [feed?.nextUpdate, refresh]);

  const rows = useMemo(
    () => (feed ? buildRows(feed.vulnerabilities, assets, triage, feed.today) : []),
    [feed, assets, triage],
  );
  const plantao = useMemo(() => (feed ? describePlantao(rows, feed.today) : null), [feed, rows]);
  const queueRows = useMemo(() => {
    const today = feed?.today ?? "1970-01-01";
    const known = new Set((feed?.vulnerabilities ?? []).map((item) => item.id));
    const extra = nist.filter((item) => !known.has(item.id));
    return buildRows([...(feed?.vulnerabilities ?? []), ...extra], assets, triage, today);
  }, [feed, nist, assets, triage]);
  const visible = useMemo(
    () => filterRows(queueRows, query.trim().length >= 3 ? "tudo" : filter, query),
    [queueRows, filter, query],
  );
  const openRow = queueRows.find((row) => row.vuln.id === openId) ?? null;
  const failed = feed?.sources.filter((source) => !source.ok) ?? [];

  function updateAssets(next: Asset[]) {
    setAssets(next);
  }

  function saveTriageEntry(id: string, status: TriageStatus, note: string) {
    setTriage({
      ...triage,
      [id]: { status, note, updatedAt: new Date().toISOString() },
    });
  }

  return (
    <div className="min-h-screen bg-[#e8e2d6] text-[#1c1915]">
      <header className="sticky top-0 z-20 border-b border-[#2a3b33] bg-[#1b2822] text-[#f6f1e7] md:hidden">
        <div className="flex items-center justify-between px-4 py-3">
          <Wordmark />
          <Button
            type="button"
            size="sm"
            variant="secondary"
            disabled={loading}
            onClick={() => void refresh()}
          >
            {loading ? "Atualizando" : "Atualizar"}
          </Button>
        </div>
        <nav className="flex gap-1 overflow-x-auto px-3 pb-3" aria-label="Seções">
          {VIEWS.map((item) => (
            <NavButton key={item.id} current={view === item.id} onClick={() => setView(item.id)}>
              {item.label}
            </NavButton>
          ))}
        </nav>
      </header>

      <div className="md:grid md:grid-cols-[240px_minmax(0,1fr)]">
        <aside className="sticky top-0 hidden h-screen flex-col bg-[#1b2822] text-[#f6f1e7] md:flex">
          <div className="px-5 pt-6">
            <Wordmark />
            {feed ? (
              <p className="mt-3 text-sm text-[#c9d5ce]">
                {formatLongDay(feed.today)}
                <span className="mt-1 block text-xs text-[#b7c6be]">
                  Próxima coleta às {formatUpdateHour(feed.nextUpdate)}
                </span>
              </p>
            ) : null}
          </div>
          <nav className="mt-8 flex flex-col gap-1 px-3" aria-label="Seções">
            {VIEWS.map((item) => (
              <NavButton key={item.id} current={view === item.id} onClick={() => setView(item.id)}>
                {item.label}
              </NavButton>
            ))}
          </nav>
          <div className="mt-auto px-5 pb-6">
            <Button
              type="button"
              variant="secondary"
              disabled={loading}
              onClick={() => void refresh()}
            >
              {loading ? "Atualizando" : PUBLISHED ? "Recarregar coleta" : "Atualizar fontes"}
            </Button>
          </div>
        </aside>

        <main className="mx-auto w-full max-w-5xl px-4 py-6 md:px-8 md:py-8">
          {feed ? (
            <p className="mb-4 text-sm text-[#6b6256] md:hidden">
              {formatLongDay(feed.today)} · próxima coleta às {formatUpdateHour(feed.nextUpdate)}
            </p>
          ) : null}
          {failed.length > 0 ? (
            <p className="mb-4 rounded-lg border border-[#e2c9a2] bg-[#fff6e8] px-3 py-2 text-sm text-[#6b4a16]">
              {failed.map((source) => source.error).join(" ")} O plantão segue com o que chegou.
            </p>
          ) : null}
          {error ? (
            <div className="mb-4 rounded-lg border border-dashed border-[#d3c8b4] bg-[#fffcf7] px-4 py-4">
              <p className="text-sm text-[#5c564c]">{error}</p>
              <Button className="mt-3" type="button" onClick={() => void refresh()}>
                Tentar de novo
              </Button>
            </div>
          ) : null}
          {loading && !feed && !error ? (
            <p className="text-sm text-[#5c564c]">
              Consultando o catálogo CISA KEV, o NIST NVD e o CERT.br. A primeira leitura pode levar alguns segundos.
            </p>
          ) : null}
          {feed && plantao && view === "briefing" ? (
            <BriefingView
              text={plantao.text}
              stats={plantao.stats}
              rows={rows}
              notices={feed.notices}
              sources={feed.sources}
              onOpen={setOpenId}
            />
          ) : null}
          {view === "correcoes" ? <FixesView rows={queueRows} onOpen={setOpenId} /> : null}
          {view === "fila" ? (
            <QueueView
              rows={visible}
              filter={filter}
              query={query}
              nistNote={nistNote}
              onFilter={setFilter}
              onQuery={setQuery}
              onOpen={setOpenId}
            />
          ) : null}
          {view === "ativos" ? <AssetsView assets={assets} onChange={updateAssets} /> : null}
          {view === "fontes" ? (
            <SourcesView
              sources={feed?.sources ?? []}
              fetchedAt={feed?.fetchedAt ?? null}
              today={feed?.today ?? null}
              published={PUBLISHED}
            />
          ) : null}
        </main>
      </div>

      <VulnSheet row={openRow} onClose={() => setOpenId(null)} onSave={saveTriageEntry} />
    </div>
  );
}

async function requestFeed(refreshFeed: boolean, signal?: AbortSignal): Promise<FeedResponse> {
  const url = PUBLISHED
    ? `${BASE_PATH}/feed.json${refreshFeed ? `?t=${Date.now()}` : ""}`
    : refreshFeed
      ? "/api/feed?refresh=1"
      : "/api/feed";
  const response = await fetch(url, {
    cache: "no-store",
    signal,
  });
  if (!response.ok) throw new Error("feed");
  return (await response.json()) as FeedResponse;
}

function Wordmark() {
  return (
    <div>
      <p className="font-serif text-2xl tracking-tight text-[#f6f1e7]">Ronda</p>
      <p className="text-xs tracking-[0.14em] text-[#b7c6be] uppercase">Plantão de vulnerabilidades</p>
    </div>
  );
}

function NavButton({
  current,
  onClick,
  children,
}: {
  current: boolean;
  onClick: () => void;
  children: string;
}) {
  return (
    <button
      type="button"
      aria-current={current ? "page" : undefined}
      onClick={onClick}
      className={
        current
          ? "rounded-md bg-[#f6f1e7] px-3 py-1.5 text-left text-sm font-medium text-[#1b2822]"
          : "rounded-md px-3 py-1.5 text-left text-sm text-[#d5e0da] hover:bg-[#24362e]"
      }
    >
      {children}
    </button>
  );
}
