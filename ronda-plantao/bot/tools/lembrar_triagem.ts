import { defineTool } from "@grok/agent-sdk/tools";
import * as z from "zod/v4";
import { carregarColeta, type FonteColeta } from "../lib/coleta.js";
import { aplicarTriagem, STATUS_TRIAGEM, type ItemAberto } from "../lib/triagem.js";

const limitePadrao = 8;

type TriagemResposta = {
  fonte: FonteColeta;
  aviso: string | null;
  triagemInformada: boolean;
  hoje: string;
  contagem: {
    consideradas: number;
    semTriagem: number;
    emAberto: number;
    fechados: number;
    prazoCatalogoVencido: number;
    listadas: number;
  };
  foraDaColeta: string[];
  foraDaColetaQuantidade: number;
  itens: ItemAberto[];
};

const AVISO_NAVEGADOR =
  "A triagem e os ativos ficam no navegador da Ronda, na Fila. Sem o mapa, cada item abaixo segue como sem triagem.";

export default defineTool({
  description:
    "Cruza a coleta com um mapa opcional de triagem (id e status) colado pela pessoa. Não grava nada: a triagem real fica no navegador. Devolve os itens altos, críticos ou do KEV que ainda estão abertos. Não descreve exploração.",
  effect: "read",
  execution: "server",
  inputSchema: z.object({
    triagem: z
      .array(
        z.object({
          id: z.string().trim().min(3).max(40),
          status: z.enum(STATUS_TRIAGEM),
        }),
      )
      .max(80)
      .optional(),
    limite: z.number().int().min(1).max(12).optional(),
    usarExemplo: z.boolean().optional(),
  }),
  async execute({ triagem, limite, usarExemplo }): Promise<TriagemResposta> {
    const coleta = await carregarColeta(usarExemplo === true);
    const aplicada = aplicarTriagem(coleta, triagem, limite ?? limitePadrao);
    const aviso = [coleta.aviso, aplicada.triagemInformada ? null : AVISO_NAVEGADOR].filter(Boolean).join(" ");
    return {
      fonte: coleta.fonte,
      aviso: aviso || null,
      triagemInformada: aplicada.triagemInformada,
      hoje: coleta.hoje,
      contagem: {
        consideradas: aplicada.consideradas,
        semTriagem: aplicada.semTriagem,
        emAberto: aplicada.emAberto,
        fechados: aplicada.fechados,
        prazoCatalogoVencido: aplicada.prazoCatalogoVencido,
        listadas: aplicada.itens.length,
      },
      foraDaColeta: aplicada.foraDaColeta,
      foraDaColetaQuantidade: aplicada.foraDaColetaQuantidade,
      itens: aplicada.itens,
    };
  },
});
