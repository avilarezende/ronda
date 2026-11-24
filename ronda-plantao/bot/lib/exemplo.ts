// Coleta sintética para o agente responder sem rede e sem a chave do VulDB.
// Os identificadores não são CVEs reais.
export const COLETA_EXEMPLO = {
  fetchedAt: "2026-11-24T08:00:00.000Z",
  today: "2026-11-24",
  sources: [
    { id: "cisa-kev", label: "CISA KEV", ok: true, count: 1 },
    { id: "nvd", label: "NIST NVD", ok: true, count: 1 },
    { id: "osv", label: "OSV.dev", ok: true, count: 0 },
    {
      id: "vuldb",
      label: "VulDB",
      ok: false,
      count: 0,
      error: "A coleta de exemplo não inclui o VulDB.",
    },
    { id: "certbr", label: "CERT.br", ok: true, count: 1 },
  ],
  vulnerabilities: [
    {
      id: "EXEMPLO-CRITICA",
      name: "Produto de demonstração — prioridade de catálogo",
      vendor: "Exemplo",
      product: "Produto de demonstração",
      published: "2026-11-20",
      severity: "critical",
      cvss: 9.8,
      kev: true,
      ransomware: "Unknown",
      dueDate: "2026-11-01",
      references: [
        { label: "Catálogo KEV", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      ],
      remediation: {
        kind: "contorno",
        summary:
          "Enquanto a atualização não estiver aplicada, siga o contorno publicado pelo fabricante ou pela CISA.",
      },
    },
    {
      id: "EXEMPLO-ALTA",
      name: "Biblioteca de demonstração — atualização publicada",
      vendor: "Exemplo",
      product: "Biblioteca de demonstração",
      published: "2026-11-18",
      severity: "high",
      cvss: 7.5,
      kev: false,
      ransomware: null,
      dueDate: null,
      references: [{ label: "NIST", href: "https://nvd.nist.gov/" }],
      remediation: {
        kind: "correcao",
        summary: "Há correção publicada pelo fabricante. Aplique a atualização indicada no aviso.",
      },
    },
  ],
  notices: [
    {
      title: "Aviso de exemplo do CERT.br",
      published: "2026-11-22",
      href: "https://www.cert.br/",
    },
  ],
};
