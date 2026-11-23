import { FixMark, PriorityMark, SeverityMark, StatusMark } from "@/components/marks";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { QueueFilter, Row } from "@/lib/rows";
import { formatDay } from "@/lib/text";

const FILTERS: Array<{ id: QueueFilter; label: string }> = [
  { id: "olhar", label: "Precisam de olhar" },
  { id: "kev", label: "No KEV" },
  { id: "ativos", label: "Nos meus ativos" },
  { id: "tudo", label: "Tudo" },
];

export function QueueView({
  rows,
  filter,
  query,
  nistNote,
  onFilter,
  onQuery,
  onOpen,
}: {
  rows: Row[];
  filter: QueueFilter;
  query: string;
  nistNote: string | null;
  onFilter: (filter: QueueFilter) => void;
  onQuery: (query: string) => void;
  onOpen: (id: string) => void;
}) {
  return (
    <div>
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div className="-mx-4 flex flex-nowrap gap-2 overflow-x-auto px-4 pb-1 md:mx-0 md:px-0">
          {FILTERS.map((item) => (
            <Button
              key={item.id}
              type="button"
              size="sm"
              variant={filter === item.id ? "default" : "outline"}
              onClick={() => onFilter(item.id)}
            >
              {item.label}
            </Button>
          ))}
        </div>
        <Input
          value={query}
          onChange={(event) => onQuery(event.target.value)}
          placeholder="Buscar na fila e no NIST"
          aria-label="Buscar na fila e no NIST"
          className="md:max-w-xs"
        />
      </div>
      <p className="mt-3 text-xs text-[#6b6256]">
        {rows.length === 1 ? "1 item" : `${rows.length} itens`}
        {nistNote ? ` · ${nistNote}` : ""}
      </p>
      {rows.length === 0 ? (
        <p className="mt-4 rounded-lg border border-dashed border-[#d3c8b4] bg-[#fffcf7] px-4 py-8 text-sm text-[#5c564c]">
          Nenhum item com esse recorte. Troque o filtro ou cadastre um ativo com outra palavra-chave.
        </p>
      ) : (
        <ul className="mt-2 divide-y divide-[#eadfce] rounded-lg border border-[#ddd4c4] bg-[#fffcf7]">
          {rows.map((row) => (
            <li key={row.vuln.id}>
              <button
                type="button"
                onClick={() => onOpen(row.vuln.id)}
                className="flex flex-col items-start gap-2 px-4 py-3 text-left hover:bg-[#f7f3ea] md:grid md:w-full md:grid-cols-[9.5rem_1fr_auto] md:items-center"
              >
                <span className="font-mono text-xs text-[#6b6256]">{row.vuln.id}</span>
                <span>
                  <span className="block text-sm font-medium text-[#1c1915]">
                    {row.vuln.vendor} · {row.vuln.product}
                  </span>
                  <span className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-[#6b6256]">
                    <span>{formatDay(row.vuln.published)}</span>
                    <SeverityMark severity={row.vuln.severity} score={row.vuln.cvss} />
                    {row.vuln.kev ? <span>KEV</span> : null}
                    {row.match.assets.length > 0 ? (
                      <span>{row.match.assets.map((asset) => asset.name).join(", ")}</span>
                    ) : null}
                    <StatusMark status={row.status} />
                    {row.vuln.remediation ? <FixMark kind={row.vuln.remediation.kind} /> : null}
                  </span>
                </span>
                <PriorityMark priority={row.match.priority} />
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
