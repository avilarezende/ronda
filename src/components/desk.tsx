"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { AssetsView } from "@/components/assets-view";
import { BriefingView } from "@/components/briefing-view";
import { QueueView } from "@/components/queue-view";
import { SourcesView } from "@/components/sources-view";
import { Button } from "@/components/ui/button";
import { VulnSheet } from "@/components/vuln-sheet";
import { buildRows, describePlantao, filterRows, type QueueFilter } from "@/lib/rows";
import { useAssets, useTriage } from "@/lib/storage";
import { formatLongDay } from "@/lib/text";
import type { Asset, FeedResponse, TriageStatus } from "@/lib/types";

type View = "briefing" | "fila" | "ativos" | "fontes";

const VIEWS: Array<{ id: View; label: string }> = [
  { id: "briefing", label: "Briefing" },
  { id: "fila", label: "Fila" },
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

  const rows = useMemo(
    () => (feed ? buildRows(feed.vulnerabilities, assets, triage, feed.today) : []),
    [feed, assets, triage],
  );
  const plantao = useMemo(() => (feed ? describePlantao(rows, feed.today) : null), [feed, rows]);
  const visible = useMemo(() => filterRows(rows, filter, query), [rows, filter, query]);
  const openRow = rows.find((row) => row.vuln.id === openId) ?? null;
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
            <p className="mt-3 text-sm text-[#c9d5ce]">{formatLongDay()}</p>
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
              {loading ? "Atualizando" : "Atualizar fontes"}
            </Button>
          </div>
        </aside>

        <main className="mx-auto w-full max-w-5xl px-4 py-6 md:px-8 md:py-8">
          <p className="mb-4 text-sm text-[#6b6256] md:hidden">{formatLongDay()}</p>
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
              Consultando o catálogo CISA KEV, a NVD e o CERT.br. A primeira leitura pode levar alguns segundos.
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
          {feed && view === "fila" ? (
            <QueueView
              rows={visible}
              filter={filter}
              query={query}
              onFilter={setFilter}
              onQuery={setQuery}
              onOpen={setOpenId}
            />
          ) : null}
          {view === "ativos" ? <AssetsView assets={assets} onChange={updateAssets} /> : null}
          {view === "fontes" ? (
            <SourcesView sources={feed?.sources ?? []} fetchedAt={feed?.fetchedAt ?? null} />
          ) : null}
        </main>
      </div>

      <VulnSheet row={openRow} onClose={() => setOpenId(null)} onSave={saveTriageEntry} />
    </div>
  );
}

async function requestFeed(refreshFeed: boolean, signal?: AbortSignal): Promise<FeedResponse> {
  const response = await fetch(refreshFeed ? "/api/feed?refresh=1" : "/api/feed", {
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
