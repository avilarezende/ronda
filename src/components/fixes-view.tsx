import { FixMark, PriorityMark } from "@/components/marks";
import type { Row } from "@/lib/rows";

export function FixesView({ rows, onOpen }: { rows: Row[]; onOpen: (id: string) => void }) {
  const fixes = rows.filter((row) => row.vuln.remediation);
  const corrections = fixes.filter((row) => row.vuln.remediation?.kind === "correcao").length;

  return (
    <div>
      <p className="max-w-2xl text-sm leading-relaxed text-[#3f382f]">
        Correção é atualização publicada pelo fabricante. Contorno é a medida indicada pela CISA ou pelo fabricante enquanto essa atualização não entra no ambiente.
      </p>
      <p className="mt-3 text-xs text-[#6b6256]">
        {fixes.length === 1 ? "1 item" : `${fixes.length} itens`}
        {corrections > 0 ? ` · ${corrections} com correção` : ""}
      </p>
      {fixes.length === 0 ? (
        <p className="mt-4 rounded-lg border border-dashed border-[#d3c8b4] bg-[#fffcf7] px-4 py-8 text-sm text-[#5c564c]">
          Nenhuma correção ou contorno identificado nesta coleta.
        </p>
      ) : (
        <ul className="mt-2 divide-y divide-[#eadfce] rounded-lg border border-[#ddd4c4] bg-[#fffcf7]">
          {fixes.map((row) => (
            <li key={row.vuln.id}>
              <button
                type="button"
                onClick={() => onOpen(row.vuln.id)}
                className="w-full px-4 py-3 text-left hover:bg-[#f7f3ea]"
              >
                <span className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs text-[#6b6256]">{row.vuln.id}</span>
                  {row.vuln.remediation ? <FixMark kind={row.vuln.remediation.kind} /> : null}
                  <PriorityMark priority={row.match.priority} />
                </span>
                <span className="mt-1 block text-sm font-medium">
                  {row.vuln.vendor} · {row.vuln.product}
                </span>
                <span className="mt-1 block text-sm leading-relaxed text-[#3f382f]">
                  {row.vuln.remediation?.summary}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
