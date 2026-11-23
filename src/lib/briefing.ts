export type BriefingInput = {
  kevRecent: number;
  matched: number;
  matchedEssential: number;
  openTriage: number;
  overdue: number;
  top: { id: string; vendor: string; product: string } | null;
};

function itemLabel(count: number, singular: string, plural: string): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

export function writeBriefing(input: BriefingInput): string {
  const parts: string[] = [];

  if (input.kevRecent === 0) {
    parts.push("O catálogo CISA KEV não recebeu entradas novas nos últimos 7 dias.");
  } else {
    parts.push(
      `O catálogo CISA KEV recebeu ${itemLabel(input.kevRecent, "entrada", "entradas")} nos últimos 7 dias.`,
    );
  }

  if (input.matched === 0) {
    parts.push("Nenhuma vulnerabilidade da fila conversa com os ativos cadastrados.");
  } else if (input.matchedEssential === 0) {
    parts.push(
      `${itemLabel(input.matched, "item conversa", "itens conversam")} com ativos cadastrados.`,
    );
  } else {
    const essential =
      input.matchedEssential === 1
        ? "um deles em ativo essencial"
        : `${input.matchedEssential} deles em ativo essencial`;
    parts.push(
      `${itemLabel(input.matched, "item conversa", "itens conversam")} com ativos cadastrados, ${essential}.`,
    );
  }

  if (input.overdue > 0) {
    parts.push(
      input.overdue === 1
        ? "Um item do KEV que conversa com ativo cadastrado passou do prazo indicado pela CISA e ainda não foi marcado como mitigado."
        : `${input.overdue} itens do KEV que conversam com ativo cadastrado passaram do prazo indicado pela CISA e ainda não foram marcados como mitigados.`,
    );
  }

  if (input.openTriage === 0) {
    parts.push("A fila visível está triada.");
  } else {
    parts.push(`${itemLabel(input.openTriage, "item segue", "itens seguem")} sem triagem.`);
  }

  if (input.top) {
    parts.push(
      `A primeira da fila é ${input.top.id}, ${input.top.vendor} ${input.top.product}.`,
    );
  }

  return parts.join(" ");
}
