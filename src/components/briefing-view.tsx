import { PriorityMark } from "@/components/marks";
import type { BriefingInput } from "@/lib/briefing";
import { defensiveAction } from "@/lib/match";
import type { Row } from "@/lib/rows";
import type { Notice, SourceReport } from "@/lib/types";
import { formatDay } from "@/lib/text";

export function BriefingView({
  text,
  stats,
  rows,
  notices,
  sources,
  onOpen,
}: {
  text: string;
  stats: BriefingInput;
  rows: Row[];
  notices: Notice[];
  sources: SourceReport[];
  onOpen: (id: string) => void;
}) {
  const spotlight = rows
    .filter((row) => row.match.priority === "urgente" || row.match.priority === "alta")
    .slice(0, 5);
  const collected = sources.filter((source) => source.ok).length;

  return (
    <div className="space-y-8">
      <p className="max-w-3xl font-serif text-2xl leading-snug text-[#1c1915] md:text-[1.7rem]">
        {text}
      </p>

      <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-[#ddd4c4] bg-[#ddd4c4] md:grid-cols-4">
        <Stat value={stats.kevRecent} label="KEV em 7 dias" />
        <Stat value={stats.matched} label="nos seus ativos" />
        <Stat value={stats.overdue} label="prazo vencido" />
        <Stat value={stats.openTriage} label="sem triagem" />
      </dl>

      <section>
        <h2 className="text-xs font-medium tracking-[0.16em] text-[#6b6256] uppercase">
          Agentes deste plantão
        </h2>
        <ol className="mt-3 divide-y divide-[#eadfce] rounded-lg border border-[#ddd4c4] bg-[#fffcf7]">
          <Agent
            index="01"
            name="Coleta"
            detail={
              collected === sources.length
                ? "CISA KEV, NVD e CERT.br responderam."
                : `${collected} de ${sources.length} fontes responderam. O restante fica registrado em Fontes.`
            }
          />
          <Agent
            index="02"
            name="Correspondência"
            detail={
              stats.matched === 0
                ? "Nenhum item da fila encontrou palavra-chave dos ativos."
                : `${stats.matched} itens encontraram palavra-chave de ativo cadastrado.`
            }
          />
          <Agent
            index="03"
            name="Briefing"
            detail="Ordena pelo catálogo KEV, pela severidade, pelo prazo e pela criticidade do ativo. A orientação é confirmar exposição e aplicar a atualização do fabricante."
          />
        </ol>
      </section>

      <section>
        <h2 className="text-xs font-medium tracking-[0.16em] text-[#6b6256] uppercase">
          Prioridade do plantão
        </h2>
        {spotlight.length === 0 ? (
          <p className="mt-3 rounded-lg border border-dashed border-[#d3c8b4] bg-[#fffcf7] px-4 py-6 text-sm text-[#5c564c]">
            Nada urgente ou alto com os ativos atuais. A fila completa continua disponível para triagem.
          </p>
        ) : (
          <ul className="mt-3 divide-y divide-[#eadfce] rounded-lg border border-[#ddd4c4] bg-[#fffcf7]">
            {spotlight.map((row) => (
              <li key={row.vuln.id}>
                <button
                  type="button"
                  onClick={() => onOpen(row.vuln.id)}
                  className="w-full px-4 py-4 text-left hover:bg-[#f7f3ea]"
                >
                  <div className="flex items-center justify-between gap-3">
                    <span className="font-mono text-xs text-[#6b6256]">{row.vuln.id}</span>
                    <PriorityMark priority={row.match.priority} />
                  </div>
                  <p className="mt-1 font-serif text-lg text-[#1c1915]">
                    {row.vuln.vendor} {row.vuln.product}
                  </p>
                  <p className="mt-1 text-sm leading-relaxed text-[#3f382f]">
                    {defensiveAction(row.vuln, row.match.assets.length > 0)}
                  </p>
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <h2 className="text-xs font-medium tracking-[0.16em] text-[#6b6256] uppercase">
          Novidades do CERT.br
        </h2>
        {notices.length === 0 ? (
          <p className="mt-3 text-sm text-[#5c564c]">Nenhuma novidade disponível nesta consulta.</p>
        ) : (
          <ul className="mt-3 space-y-3">
            {notices.map((notice) => (
              <li key={notice.id} className="border-l-2 border-[#1f4336] pl-3">
                <a
                  href={notice.href}
                  target="_blank"
                  rel="noreferrer"
                  className="font-medium text-[#1f4336] underline-offset-4 hover:underline"
                >
                  {notice.title}
                </a>
                {notice.published ? (
                  <p className="text-xs text-[#6b6256]">{formatDay(notice.published)}</p>
                ) : null}
                {notice.summary ? (
                  <p className="mt-1 text-sm leading-relaxed text-[#3f382f]">{notice.summary}</p>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function Stat({ value, label }: { value: number; label: string }) {
  return (
    <div className="bg-[#fffcf7] px-4 py-3">
      <dt className="text-xs text-[#6b6256]">{label}</dt>
      <dd className="mt-1 font-serif text-3xl text-[#1c1915]">{value}</dd>
    </div>
  );
}

function Agent({ index, name, detail }: { index: string; name: string; detail: string }) {
  return (
    <li className="grid grid-cols-[auto_1fr] gap-3 px-4 py-3">
      <span className="font-mono text-xs text-[#8a5a12]">{index}</span>
      <div>
        <p className="text-sm font-medium">{name}</p>
        <p className="text-sm leading-relaxed text-[#5c564c]">{detail}</p>
      </div>
    </li>
  );
}
