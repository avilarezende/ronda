import type { Asset, Priority, Vuln } from "@/lib/types";
import { containsPhrase, daysBetween } from "@/lib/text";

export type Match = {
  score: number;
  priority: Priority;
  assets: Asset[];
  reasons: string[];
};

export function assess(vuln: Vuln, assets: Asset[], today: string): Match {
  const haystack = `${vuln.vendor} ${vuln.product} ${vuln.name} ${vuln.summary}`;
  const hits = assets.filter((asset) =>
    asset.keywords.some((keyword) => containsPhrase(haystack, keyword)),
  );

  let score = 0;
  const reasons: string[] = [];

  if (vuln.kev) {
    score += 40;
    reasons.push("Consta no catálogo CISA KEV");
  }
  if (vuln.ransomware === "Known") {
    score += 20;
    reasons.push("A CISA registrou uso em campanha de ransomware");
  }
  if (vuln.severity === "critical") {
    score += 20;
    reasons.push("Severidade crítica");
  } else if (vuln.severity === "high") {
    score += 12;
    reasons.push("Severidade alta");
  } else if (vuln.severity === "medium") {
    score += 4;
  }

  const essential = hits.filter((asset) => asset.criticality === "essencial");
  const important = hits.filter((asset) => asset.criticality === "importante");
  if (essential.length > 0) {
    score += 30;
    reasons.push(`Ativo essencial: ${essential.map((asset) => asset.name).join(", ")}`);
  } else if (important.length > 0) {
    score += 16;
    reasons.push(`Ativo importante: ${important.map((asset) => asset.name).join(", ")}`);
  } else if (hits.length > 0) {
    score += 8;
    reasons.push(`Ativo acompanhado: ${hits.map((asset) => asset.name).join(", ")}`);
  }

  if (vuln.dueDate && hits.length > 0) {
    const remaining = daysBetween(vuln.dueDate, today);
    if (remaining < 0) {
      score += 15;
      reasons.push("Prazo indicado pela CISA já vencido");
    } else if (remaining <= 3) {
      score += 12;
      reasons.push("Prazo indicado pela CISA em até 3 dias");
    }
  }

  let priority: Priority = "baixa";
  if (score >= 70) priority = "urgente";
  else if (score >= 45) priority = "alta";
  else if (score >= 20) priority = "media";

  return { score, priority, assets: hits, reasons };
}

export function defensiveAction(vuln: Vuln, matched: boolean): string {
  const forensic = vuln.forensicTriage
    ? " A CISA sinalizou triagem forense para este item."
    : "";
  if (vuln.kev && matched) {
    return `O item está no catálogo CISA KEV e conversa com um ativo cadastrado. Confirme a exposição e aplique a atualização publicada pelo fabricante.${forensic}`;
  }
  if (vuln.kev) {
    return `O item está no catálogo CISA KEV. Confirme se o produto existe no ambiente e, se existir, aplique a atualização do fabricante.${forensic}`;
  }
  if (matched) {
    return "Há correspondência com um ativo cadastrado. Confirme a versão afetada e aplique a atualização publicada pelo fabricante.";
  }
  return "Sem correspondência com os ativos cadastrados. Se o produto não estiver no ambiente, marque como não afeta.";
}
