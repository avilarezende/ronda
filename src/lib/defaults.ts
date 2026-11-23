import type { Asset, TriageStatus } from "@/lib/types";

export const DEFAULT_ASSETS: Asset[] = [
  {
    id: "windows",
    name: "Microsoft Windows",
    keywords: ["microsoft windows", "windows server"],
    criticality: "essencial",
    note: "Estações e servidores.",
  },
  {
    id: "microsoft-365",
    name: "Microsoft 365 e Exchange",
    keywords: ["microsoft exchange", "exchange server", "sharepoint", "microsoft 365"],
    criticality: "essencial",
    note: "Correio e colaboração.",
  },
  {
    id: "fortinet",
    name: "Fortinet",
    keywords: ["fortinet", "fortios", "fortigate"],
    criticality: "essencial",
    note: "Borda de rede.",
  },
  {
    id: "vmware",
    name: "VMware",
    keywords: ["vmware", "esxi", "vcenter"],
    criticality: "essencial",
    note: "Virtualização.",
  },
  {
    id: "linux",
    name: "Linux e OpenSSL",
    keywords: ["linux kernel", "openssl"],
    criticality: "importante",
    note: "",
  },
  {
    id: "postgres",
    name: "PostgreSQL",
    keywords: ["postgresql"],
    criticality: "importante",
    note: "",
  },
  {
    id: "cisco",
    name: "Cisco",
    keywords: ["cisco ios", "cisco asa", "cisco firepower"],
    criticality: "importante",
    note: "",
  },
  {
    id: "paloalto",
    name: "Palo Alto",
    keywords: ["palo alto", "pan-os"],
    criticality: "importante",
    note: "",
  },
  {
    id: "apache",
    name: "Apache Tomcat",
    keywords: ["apache tomcat", "apache http server"],
    criticality: "apoio",
    note: "",
  },
];

export const STATUS_LABEL: Record<TriageStatus, string> = {
  nova: "Nova",
  "em-analise": "Em análise",
  afeta: "Afeta o ambiente",
  "nao-afeta": "Não afeta",
  mitigada: "Mitigada",
  "risco-aceito": "Risco aceito",
};

export const CRITICALITY_LABEL = {
  essencial: "Essencial",
  importante: "Importante",
  apoio: "Apoio",
} as const;

export const PRIORITY_LABEL = {
  urgente: "Urgente",
  alta: "Alta",
  media: "Média",
  baixa: "Baixa",
} as const;

export const SEVERITY_LABEL = {
  critical: "Crítica",
  high: "Alta",
  medium: "Média",
  low: "Baixa",
  unknown: "Sem CVSS",
} as const;
