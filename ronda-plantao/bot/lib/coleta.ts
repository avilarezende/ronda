import { readFile } from "node:fs/promises";
import { COLETA_EXEMPLO } from "./exemplo.js";

export const FEED_PUBLICADO = "https://avilarezende.github.io/ronda/feed.json";
const LIMITE_BYTES = 2_000_000;
const TEMPO_MS = 12_000;
const CACHE_MS = 60_000;

const DICA_OFENSIVA =
  /\bonerror\b|\bonload\s*=|<script|<\/script>|msfvenom|curl\s+\||wget\s+|\/bin\/sh|union\s+select|xp_cmdshell|\$\{jndi|base64\s+-d|powershell\b|<\?php|\bpayloads?\b/i;

export type FonteColeta = "publicada" | "endereco" | "arquivo" | "exemplo";
export type SeveridadeItem = "critical" | "high" | "outra";
export type TipoRemediacao = "correcao" | "contorno";

export type FonteRelato = {
  id: string;
  rotulo: string;
  ok: boolean;
  quantidade: number;
  erro?: string;
};

export type Referencia = {
  rotulo: string;
  href: string;
};

export type ItemPlantao = {
  id: string;
  nome: string;
  fornecedor: string;
  produto: string;
  publicado: string;
  severidade: SeveridadeItem;
  cvss: number | null;
  kev: boolean;
  ransomwareConhecido: boolean;
  prazo: string | null;
  prazoCatalogoVencido: boolean;
  remediacao: TipoRemediacao | null;
  orientacao: string;
  referencias: Referencia[];
};

export type AvisoCert = {
  titulo: string;
  publicado: string;
  href: string;
};

export type Coleta = {
  fonte: FonteColeta;
  aviso: string | null;
  coletadaEm: string;
  hoje: string;
  vuldbPresente: boolean;
  fontes: FonteRelato[];
  itens: ItemPlantao[];
  avisos: AvisoCert[];
};

type Registro = Record<string, unknown>;

export type ColetaBruta = {
  fetchedAt?: string;
  today?: string;
  sources?: unknown;
  vulnerabilities?: unknown;
  notices?: unknown;
};

type Cache = { chave: string; expira: number; coleta: Coleta };
let cache: Cache | null = null;

function registro(value: unknown): value is Registro {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function texto(value: unknown, limite: number): string {
  if (typeof value !== "string") return "";
  return value.replace(/\s+/g, " ").trim().slice(0, limite);
}

function hojeFortaleza(now = new Date()): string {
  return new Intl.DateTimeFormat("en-CA", { timeZone: "America/Fortaleza" }).format(now);
}

function dia(value: string): boolean {
  return /^\d{4}-\d{2}-\d{2}$/.test(value);
}

function severidade(value: unknown): SeveridadeItem {
  if (value === "critical" || value === "high") return value;
  return "outra";
}

function nota(value: unknown): number | null {
  if (typeof value === "number") {
    if (!Number.isFinite(value) || value < 0 || value > 10) return null;
    return Math.round(value * 10) / 10;
  }
  if (typeof value !== "string") return null;
  const bruto = texto(value, 8);
  if (!bruto) return null;
  const numero = Number(bruto);
  if (!Number.isFinite(numero) || numero < 0 || numero > 10) return null;
  return Math.round(numero * 10) / 10;
}

function seguro(value: string, reserva: string): string {
  if (!value || DICA_OFENSIVA.test(value)) return reserva;
  return value;
}

function orientacaoDe(kind: TipoRemediacao | null, vinda: string): string {
  const padrao =
    kind === "correcao"
      ? "Há correção publicada pelo fabricante. Aplique a atualização indicada no aviso."
      : kind === "contorno"
        ? "Enquanto a atualização não estiver aplicada, siga o contorno publicado pelo fabricante ou pela CISA."
        : "Confirme se o produto está no ambiente e aplique a atualização publicada pelo fabricante.";
  return seguro(vinda, padrao);
}

function referenciasDe(value: unknown): Referencia[] {
  if (!Array.isArray(value)) return [];
  const links: Referencia[] = [];
  for (const item of value) {
    if (!registro(item)) continue;
    const href = texto(item.href, 300);
    if (!href.startsWith("https://") || /\s/.test(href)) continue;
    const rotulo = texto(item.label, 40) || "Referência";
    links.push({ rotulo, href });
    if (links.length === 2) break;
  }
  return links;
}

function remediacaoDe(value: unknown): { kind: TipoRemediacao | null; summary: string } {
  if (!registro(value)) return { kind: null, summary: "" };
  const kind = value.kind === "correcao" || value.kind === "contorno" ? value.kind : null;
  return { kind, summary: texto(value.summary, 240) };
}

function fontesDe(value: unknown): FonteRelato[] {
  if (!Array.isArray(value)) return [];
  const fontes: FonteRelato[] = [];
  for (const item of value) {
    if (!registro(item)) continue;
    const id = texto(item.id, 40);
    if (!id) continue;
    const erro = texto(item.error, 180);
    const fonte: FonteRelato = {
      id,
      rotulo: texto(item.label, 40) || id,
      ok: item.ok === true,
      quantidade: typeof item.count === "number" && item.count >= 0 ? Math.floor(item.count) : 0,
    };
    if (erro) fonte.erro = erro;
    fontes.push(fonte);
    if (fontes.length === 8) break;
  }
  return fontes;
}

function itensDe(value: unknown, hoje: string): ItemPlantao[] {
  if (!Array.isArray(value)) return [];
  const itens: ItemPlantao[] = [];
  for (const item of value) {
    if (!registro(item)) continue;
    const id = texto(item.id, 40);
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{2,39}$/.test(id)) continue;
    const fornecedor = texto(item.vendor, 80) || "Não identificado";
    const produto = texto(item.product, 80) || "Produto não identificado";
    const kev = item.kev === true;
    const nivel = severidade(item.severity);
    if (!kev && nivel === "outra") continue;
    const prazo = texto(item.dueDate, 10);
    const prazoValido = dia(prazo) ? prazo : null;
    const correcao = remediacaoDe(item.remediation);
    const reserva = `${fornecedor} ${produto}`;
    itens.push({
      id,
      nome: seguro(texto(item.name, 120), reserva),
      fornecedor,
      produto,
      publicado: dia(texto(item.published, 10)) ? texto(item.published, 10) : "",
      severidade: nivel,
      cvss: nota(item.cvss),
      kev,
      ransomwareConhecido: item.ransomware === "Known",
      prazo: prazoValido,
      prazoCatalogoVencido: Boolean(kev && prazoValido && prazoValido < hoje),
      remediacao: correcao.kind,
      orientacao: orientacaoDe(correcao.kind, correcao.summary),
      referencias: referenciasDe(item.references),
    });
    if (itens.length === 200) break;
  }
  return itens.sort(
    (a, b) => peso(b, hoje) - peso(a, hoje) || b.publicado.localeCompare(a.publicado) || a.id.localeCompare(b.id),
  );
}

function recente(publicado: string, hoje: string): boolean {
  if (!dia(publicado) || !dia(hoje)) return false;
  const dias = Math.round((Date.parse(`${hoje}T00:00:00Z`) - Date.parse(`${publicado}T00:00:00Z`)) / 86_400_000);
  return dias >= 0 && dias <= 7;
}

function peso(item: ItemPlantao, hoje: string): number {
  return (
    (item.severidade === "critical" ? 1000 : item.severidade === "high" ? 400 : 0) +
    (item.kev ? 200 : 0) +
    (recente(item.publicado, hoje) ? 100 : 0) +
    (item.prazoCatalogoVencido ? 50 : 0) +
    (item.ransomwareConhecido ? 25 : 0)
  );
}

function avisosDe(value: unknown): AvisoCert[] {
  if (!Array.isArray(value)) return [];
  const avisos: AvisoCert[] = [];
  for (const item of value) {
    if (!registro(item)) continue;
    const href = texto(item.href, 300);
    const titulo = seguro(texto(item.title, 140), "");
    if (!titulo || !href.startsWith("https://") || DICA_OFENSIVA.test(href)) continue;
    avisos.push({
      titulo,
      publicado: dia(texto(item.published, 10)) ? texto(item.published, 10) : "",
      href,
    });
    if (avisos.length === 3) break;
  }
  return avisos;
}

export function normalizarColeta(bruta: ColetaBruta, fonte: FonteColeta, aviso: string | null): Coleta {
  const hoje = dia(texto(bruta.today, 10)) ? texto(bruta.today, 10) : hojeFortaleza();
  const fontes = fontesDe(bruta.sources);
  const vuldb = fontes.find((item) => item.id === "vuldb");
  return {
    fonte,
    aviso,
    coletadaEm: texto(bruta.fetchedAt, 40) || new Date().toISOString(),
    hoje,
    vuldbPresente: Boolean(vuldb?.ok),
    fontes,
    itens: itensDe(bruta.vulnerabilities, hoje),
    avisos: avisosDe(bruta.notices),
  };
}

function exemplo(aviso: string): Coleta {
  return normalizarColeta(COLETA_EXEMPLO, "exemplo", aviso);
}

function enderecoPermitido(value: string): boolean {
  try {
    const url = new URL(value);
    if (url.username || url.password) return false;
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
}

async function lerArquivo(caminho: string): Promise<Coleta> {
  const corpo = await readFile(caminho, "utf8");
  if (corpo.length > LIMITE_BYTES) throw new Error("arquivo grande");
  const json = JSON.parse(corpo) as ColetaBruta;
  return normalizarColeta(json, "arquivo", null);
}

async function lerUrl(url: string): Promise<Coleta> {
  const response = await fetch(url, {
    signal: AbortSignal.timeout(TEMPO_MS),
    headers: { accept: "application/json", "user-agent": "ronda-plantao/0.1" },
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const corpo = await response.text();
  if (corpo.length > LIMITE_BYTES) throw new Error("resposta grande");
  const json = JSON.parse(corpo) as ColetaBruta;
  const fonte: FonteColeta = url === FEED_PUBLICADO ? "publicada" : "endereco";
  return normalizarColeta(json, fonte, null);
}

export async function carregarColeta(usarExemplo = false): Promise<Coleta> {
  if (usarExemplo) {
    return exemplo("Coleta de exemplo, para treino. Estes identificadores não são vulnerabilidades reais.");
  }

  const arquivo = process.env.RONDA_FEED_FILE?.trim() ?? "";
  const urlBruta = process.env.RONDA_FEED_URL?.trim() || FEED_PUBLICADO;
  const chave = arquivo ? `arquivo:${arquivo}` : `url:${urlBruta}`;
  const agora = Date.now();
  if (cache && cache.chave === chave && cache.expira > agora) return cache.coleta;

  try {
    const coleta = arquivo ? await lerArquivo(arquivo) : await lerRemota(urlBruta);
    cache = { chave, expira: agora + CACHE_MS, coleta };
    return coleta;
  } catch {
    return exemplo(
      "A coleta publicada não respondeu. Esta resposta é o exemplo local, não o plantão do dia. Confira a rede ou RONDA_FEED_URL / RONDA_FEED_FILE.",
    );
  }
}

async function lerRemota(url: string): Promise<Coleta> {
  if (!enderecoPermitido(url)) throw new Error("endereço recusado");
  return lerUrl(url);
}

export function resumir(itens: ItemPlantao[], listadas: number) {
  return {
    altasCriticas: itens.length,
    criticas: itens.filter((item) => item.severidade === "critical").length,
    altas: itens.filter((item) => item.severidade === "high").length,
    kev: itens.filter((item) => item.kev).length,
    listadas,
  };
}
