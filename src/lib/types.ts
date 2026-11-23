export type Severity = "critical" | "high" | "medium" | "low" | "unknown";

export type SourceId = "cisa-kev" | "nvd" | "certbr";

export type TriageStatus =
  | "nova"
  | "em-analise"
  | "afeta"
  | "nao-afeta"
  | "mitigada"
  | "risco-aceito";

export type Criticality = "essencial" | "importante" | "apoio";

export type Priority = "urgente" | "alta" | "media" | "baixa";

export type ReferenceLink = {
  label: string;
  href: string;
};

export type Vuln = {
  id: string;
  name: string;
  summary: string;
  vendor: string;
  product: string;
  published: string;
  severity: Severity;
  cvss: number | null;
  kev: boolean;
  ransomware: "Known" | "Unknown" | null;
  forensicTriage: boolean;
  dueDate: string | null;
  cwes: string[];
  references: ReferenceLink[];
  sources: Array<"cisa-kev" | "nvd">;
};

export type Notice = {
  id: string;
  title: string;
  summary: string;
  published: string;
  href: string;
};

export type Asset = {
  id: string;
  name: string;
  keywords: string[];
  criticality: Criticality;
  note: string;
};

export type TriageEntry = {
  status: TriageStatus;
  note: string;
  updatedAt: string;
};

export type SourceReport = {
  id: SourceId;
  label: string;
  ok: boolean;
  count: number;
  error?: string;
};

export type FeedResponse = {
  fetchedAt: string;
  today: string;
  sources: SourceReport[];
  vulnerabilities: Vuln[];
  notices: Notice[];
};
