import type { SourceReport } from "@/lib/types";
import { formatLongDay } from "@/lib/text";

export function SourcesView({
  sources,
  fetchedAt,
  today,
  published = false,
}: {
  sources: SourceReport[];
  fetchedAt: string | null;
  today: string | null;
  published?: boolean;
}) {
  const when = fetchedAt
    ? new Intl.DateTimeFormat("pt-BR", {
        timeZone: "America/Fortaleza",
        hour: "2-digit",
        minute: "2-digit",
        day: "2-digit",
        month: "short",
      }).format(new Date(fetchedAt))
    : "ainda não consultado";

  return (
    <div className="space-y-4">
      <p className="max-w-2xl text-sm leading-relaxed text-[#3f382f]">
        {published
          ? "Esta página publica a coleta às 2h, 8h, 14h e 20h, horário de Fortaleza. Recarregar coleta busca essa publicação. A busca da fila consulta o NIST ao vivo."
          : "A coleta renova às 2h, 8h, 14h e 20h, horário de Fortaleza. Com o painel aberto, a troca acontece sozinha."}{" "}
        A lista de ativos e a triagem ficam neste navegador. Última consulta: {when}, horário de Fortaleza.
        {today ? ` Hoje é ${formatLongDay(today)}.` : ""}
      </p>
      <ul className="grid gap-3 md:grid-cols-3">
        {sources.map((source) => (
          <li key={source.id} className="rounded-lg border border-[#ddd4c4] bg-[#fffcf7] p-4">
            <p className="text-xs tracking-[0.14em] text-[#6b6256] uppercase">{source.label}</p>
            <p className="mt-2 font-serif text-2xl">{source.ok ? source.count : "—"}</p>
            <p className="mt-1 text-sm text-[#5c564c]">
              {source.ok ? "Respondeu nesta consulta." : source.error}
            </p>
          </li>
        ))}
      </ul>
      <div className="rounded-lg border border-[#ddd4c4] bg-[#fffcf7] p-4 text-sm leading-relaxed text-[#3f382f]">
        <p>
          O catálogo CISA KEV reúne vulnerabilidades com uso conhecido. O NIST NVD entra com publicações recentes de severidade alta ou crítica, e a busca da fila consulta o NIST pelo produto ou pelo CVE. O CERT.br traz as novidades institucionais do centro.
        </p>
        <p className="mt-2">
          O resumo mostrado aqui é o texto público da fonte, cortado quando descreve um artefato de ataque. Os links ficam restritos ao registro do NIST, à CISA, ao CERT.br e a avisos de fabricante.
        </p>
      </div>
    </div>
  );
}
