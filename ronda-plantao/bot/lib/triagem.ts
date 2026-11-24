import type { Coleta, ItemPlantao } from "./coleta.js";

export const STATUS_TRIAGEM = ["nova", "em-analise", "afeta", "nao-afeta", "mitigada", "risco-aceito"] as const;

export type StatusTriagem = (typeof STATUS_TRIAGEM)[number];

const FECHADOS = new Set<StatusTriagem>(["nao-afeta", "mitigada", "risco-aceito"]);

export type MarcaTriagem = {
  id: string;
  status: StatusTriagem;
};

export type ItemAberto = ItemPlantao & {
  status: StatusTriagem;
};

export type TriagemAplicada = {
  triagemInformada: boolean;
  consideradas: number;
  semTriagem: number;
  emAberto: number;
  fechados: number;
  prazoCatalogoVencido: number;
  foraDaColeta: string[];
  foraDaColetaQuantidade: number;
  itens: ItemAberto[];
};

export function aplicarTriagem(coleta: Coleta, marcas: MarcaTriagem[] | undefined, limite: number): TriagemAplicada {
  const porId = new Map<string, StatusTriagem>();
  for (const marca of marcas ?? []) {
    porId.set(marca.id.trim().toUpperCase(), marca.status);
  }
  const conhecidos = new Set(coleta.itens.map((item) => item.id.toUpperCase()));
  const fora = [...porId.keys()].filter((id) => !conhecidos.has(id));
  const abertos: ItemAberto[] = [];
  let semTriagem = 0;
  let fechados = 0;
  let prazoCatalogoVencido = 0;

  for (const item of coleta.itens) {
    const status = porId.get(item.id.toUpperCase()) ?? "nova";
    if (FECHADOS.has(status)) {
      fechados += 1;
      continue;
    }
    if (status === "nova") semTriagem += 1;
    if (item.prazoCatalogoVencido) prazoCatalogoVencido += 1;
    abertos.push({ ...item, status });
  }

  return {
    triagemInformada: marcas !== undefined,
    consideradas: coleta.itens.length,
    semTriagem,
    emAberto: abertos.length,
    fechados,
    prazoCatalogoVencido,
    foraDaColeta: fora.slice(0, 5),
    foraDaColetaQuantidade: fora.length,
    itens: abertos.slice(0, limite),
  };
}
