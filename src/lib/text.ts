const PAYLOAD_HINT =
  /\bonerror\b|\bonload\s*=|<script|<\/script>|msfvenom|curl\s+\||wget\s+|\/bin\/sh|union\s+select|xp_cmdshell|\$\{jndi|base64\s+-d|powershell\b|<\?php|\bpayloads?\b/i;

export function normalize(value: string): string {
  return value
    .normalize("NFD")
    .replace(/\p{M}/gu, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

export function normalizeNistQuery(value: string): string | null {
  const cleaned = value.trim().replace(/\s+/g, " ").slice(0, 80);
  if (!/^[\p{L}\p{N} ._+-]{3,80}$/u.test(cleaned)) return null;
  return cleaned;
}

export function containsPhrase(haystack: string, phrase: string): boolean {
  const needle = normalize(phrase);
  if (needle.length < 3) return false;
  return ` ${normalize(haystack)} `.includes(` ${needle} `);
}

export function toPublicSummary(text: string, fallback: string): string {
  const clean = text.replace(/\s+/g, " ").trim();
  if (!clean || PAYLOAD_HINT.test(clean)) return fallback;
  const sentences = clean.split(/(?<=\.)\s+/).slice(0, 2).join(" ");
  if (sentences.length <= 420) return sentences;
  return `${sentences.slice(0, 417).replace(/\s+\S*$/, "")}…`;
}

export function fallbackSummary(vuln: {
  id: string;
  vendor: string;
  product: string;
}): string {
  return `${vuln.vendor} ${vuln.product}. Registro ${vuln.id}. Confirme a versão em uso e aplique a atualização publicada pelo fabricante.`;
}

export function fortalezaToday(now = new Date()): string {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/Fortaleza",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(now);
}

export function formatDay(isoDate: string): string {
  const [year, month, day] = isoDate.slice(0, 10).split("-").map(Number);
  if (!year || !month || !day) return isoDate;
  return new Intl.DateTimeFormat("pt-BR", {
    timeZone: "UTC",
    day: "2-digit",
    month: "short",
    year: "numeric",
  }).format(new Date(Date.UTC(year, month - 1, day)));
}

export function formatLongDay(isoDate: string): string {
  const [year, month, day] = isoDate.slice(0, 10).split("-").map(Number);
  if (!year || !month || !day) return isoDate;
  const formatted = new Intl.DateTimeFormat("pt-BR", {
    timeZone: "UTC",
    weekday: "long",
    day: "numeric",
    month: "long",
  }).format(new Date(Date.UTC(year, month - 1, day)));
  return formatted.charAt(0).toUpperCase() + formatted.slice(1);
}

export function daysBetween(later: string, earlier: string): number {
  const end = Date.parse(`${later.slice(0, 10)}T00:00:00Z`);
  const start = Date.parse(`${earlier.slice(0, 10)}T00:00:00Z`);
  if (Number.isNaN(end) || Number.isNaN(start)) return 0;
  return Math.round((end - start) / 86_400_000);
}

export function shiftDays(isoDate: string, days: number): string {
  const [year, month, day] = isoDate.slice(0, 10).split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
}

export function stripHtml(value: string): string {
  return value
    .replace(/<!\[CDATA\[|\]\]>/g, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/\s+/g, " ")
    .replace(/\s+([.,;:!?])/g, "$1")
    .trim();
}

export function cweName(id: string): string {
  const names: Record<string, string> = {
    "CWE-20": "validação de entrada",
    "CWE-22": "path traversal",
    "CWE-77": "injeção de comando",
    "CWE-78": "injeção de comando",
    "CWE-79": "XSS",
    "CWE-89": "injeção de SQL",
    "CWE-94": "injeção de código",
    "CWE-119": "memória",
    "CWE-125": "leitura fora dos limites",
    "CWE-200": "exposição de informação",
    "CWE-269": "gestão de privilégio",
    "CWE-276": "permissão incorreta",
    "CWE-284": "controle de acesso",
    "CWE-287": "autenticação",
    "CWE-306": "autenticação ausente",
    "CWE-352": "CSRF",
    "CWE-416": "use after free",
    "CWE-434": "upload de arquivo",
    "CWE-502": "desserialização",
    "CWE-611": "XXE",
    "CWE-787": "escrita fora dos limites",
    "CWE-798": "credencial embutida",
    "CWE-862": "autorização",
    "CWE-863": "autorização",
    "CWE-918": "SSRF",
  };
  return names[id] ?? id;
}
