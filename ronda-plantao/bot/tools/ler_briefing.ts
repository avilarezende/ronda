import { defineTool } from "@grok/agent-sdk/tools";
import * as z from "zod/v4";
import {
  carregarColeta,
  resumir,
  type AvisoCert,
  type FonteColeta,
  type FonteRelato,
  type ItemPlantao,
} from "../lib/coleta.js";

const limitePadrao = 8;

type BriefingResposta = {
  fonte: FonteColeta;
  aviso: string | null;
  coletadaEm: string;
  hoje: string;
  vuldbPresente: boolean;
  contagem: {
    altasCriticas: number;
    criticas: number;
    altas: number;
    kev: number;
    listadas: number;
  };
  fontes: FonteRelato[];
  itens: ItemPlantao[];
  avisos: AvisoCert[];
};

export default defineTool({
  description:
    "Lê a coleta da Ronda e devolve vulnerabilidades altas ou críticas, com a orientação defensiva publicada (atualização do fabricante ou contorno da CISA). Não descreve exploração. Use usarExemplo true só quando a pessoa pedir a coleta de exemplo.",
  effect: "read",
  execution: "server",
  inputSchema: z.object({
    limite: z.number().int().min(1).max(12).optional(),
    usarExemplo: z.boolean().optional(),
  }),
  async execute({ limite, usarExemplo }): Promise<BriefingResposta> {
    const coleta = await carregarColeta(usarExemplo === true);
    const quantidade = limite ?? limitePadrao;
    const itens = coleta.itens.slice(0, quantidade);
    return {
      fonte: coleta.fonte,
      aviso: coleta.aviso,
      coletadaEm: coleta.coletadaEm,
      hoje: coleta.hoje,
      vuldbPresente: coleta.vuldbPresente,
      contagem: resumir(coleta.itens, itens.length),
      fontes: coleta.fontes,
      itens,
      avisos: coleta.avisos,
    };
  },
});
