"use client";

import { useState } from "react";
import { toast } from "sonner";
import { PriorityMark, SeverityMark } from "@/components/marks";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import { STATUS_LABEL } from "@/lib/defaults";
import { defensiveAction } from "@/lib/match";
import type { SaveResult } from "@/lib/storage";
import type { Row } from "@/lib/rows";
import type { TriageStatus } from "@/lib/types";
import { formatDay } from "@/lib/text";

const STATUSES = Object.entries(STATUS_LABEL) as Array<[TriageStatus, string]>;

export function VulnSheet({
  row,
  onClose,
  onSave,
}: {
  row: Row | null;
  onClose: () => void;
  onSave: (id: string, status: TriageStatus, note: string) => SaveResult;
}) {
  return (
    <Sheet open={row !== null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full overflow-y-auto data-[side=right]:sm:max-w-xl">
        {row ? (
          <TriageForm key={row.vuln.id} row={row} onSave={onSave} />
        ) : null}
      </SheetContent>
    </Sheet>
  );
}

function TriageForm({
  row,
  onSave,
}: {
  row: Row;
  onSave: (id: string, status: TriageStatus, note: string) => SaveResult;
}) {
  const [status, setStatus] = useState<TriageStatus>(row.status);
  const [note, setNote] = useState(row.note);

  return (
    <>
            <SheetHeader>
              <SheetTitle className="font-mono text-sm">{row.vuln.id}</SheetTitle>
              <SheetDescription className="font-serif text-xl text-[#1c1915]">
                {row.vuln.vendor} {row.vuln.product}
              </SheetDescription>
            </SheetHeader>
            <div className="space-y-4 px-4 pb-6">
              <div className="flex flex-wrap items-center gap-2">
                <PriorityMark priority={row.match.priority} />
                <SeverityMark severity={row.vuln.severity} score={row.vuln.cvss} />
                {row.vuln.kev ? <span className="text-xs text-[#1f4336]">CISA KEV</span> : null}
                <span className="text-xs text-[#6b6256]">{formatDay(row.vuln.published)}</span>
                {row.vuln.dueDate ? (
                  <span className="text-xs text-[#6b6256]">prazo {formatDay(row.vuln.dueDate)}</span>
                ) : null}
              </div>
              <p className="text-sm leading-relaxed text-[#3f382f]">{row.vuln.summary}</p>
              <div className="rounded-lg bg-[#e7f0eb] px-3 py-3 text-sm leading-relaxed text-[#1f4336]">
                {row.vuln.remediation ? <span className="mb-1 block font-medium">{row.vuln.remediation.summary}</span> : null}
                {defensiveAction(row.vuln, row.match.assets.length > 0)}
              </div>
              {row.match.reasons.length > 0 ? (
                <ul className="list-disc space-y-1 pl-4 text-sm text-[#3f382f]">
                  {row.match.reasons.map((reason) => (
                    <li key={reason}>{reason}</li>
                  ))}
                </ul>
              ) : null}
              {row.vuln.cwes.length > 0 ? (
                <p className="text-xs text-[#6b6256]">{row.vuln.cwes.join(" · ")}</p>
              ) : null}
              <ul className="flex flex-wrap gap-3 text-sm">
                {row.vuln.references.map((link, index) => (
                  <li key={`${link.href}-${index}`}>
                    <a
                      href={link.href}
                      target="_blank"
                      rel="noreferrer"
                      className="text-[#1f4336] underline-offset-4 hover:underline"
                    >
                      {link.label}
                    </a>
                  </li>
                ))}
              </ul>
              <div className="space-y-1.5">
                <Label>Triagem</Label>
                <Select
                  value={status}
                  onValueChange={(value) => {
                    if (value && value in STATUS_LABEL) setStatus(value as TriageStatus);
                  }}
                >
                  <SelectTrigger className="w-full">
                    <SelectValue>{STATUS_LABEL[status]}</SelectValue>
                  </SelectTrigger>
                  <SelectContent>
                    {STATUSES.map(([value, label]) => (
                      <SelectItem key={value} value={value}>
                        {label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="triage-note">Nota do plantão</Label>
                <Textarea
                  id="triage-note"
                  value={note}
                  onChange={(event) => setNote(event.target.value)}
                  placeholder="Onde verificou, qual versão, qual mudança ficou pendente"
                />
              </div>
              <Button
                type="button"
                onClick={() => {
                  const saved = onSave(row.vuln.id, status, note);
                  if (saved.ok) toast.success("Triagem gravada neste navegador. Ela não vai para o GitHub.");
                  else toast.error(saved.error);
                }}
              >
                Salvar triagem
              </Button>
              <p className="text-xs text-[#6b6256]">
                A triagem e a nota ficam neste navegador, mesmo depois de fechar a aba, e não vão para o GitHub.
              </p>
            </div>
    </>
  );
}
