import type { Remediation } from "@/lib/types";

export function remediationFor(input: { patch: boolean; mitigation: boolean; kev: boolean }): Remediation | null {
  if (input.patch) {
    return {
      kind: "correcao",
      summary: "Há correção publicada pelo fabricante. Aplique a atualização indicada no aviso.",
    };
  }
  if (input.mitigation || input.kev) {
    return {
      kind: "contorno",
      summary: "Enquanto a atualização não estiver aplicada, siga o contorno publicado pelo fabricante ou pela CISA.",
    };
  }
  return null;
}

export function preferRemediation(current: Remediation | null, incoming: Remediation | null): Remediation | null {
  if (current?.kind === "correcao" || incoming?.kind === "correcao") {
    return current?.kind === "correcao" ? current : incoming;
  }
  return current ?? incoming;
}
