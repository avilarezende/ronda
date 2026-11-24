import { useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { CRITICALITY_LABEL, DEFAULT_ASSETS } from "@/lib/defaults";
import type { SaveResult } from "@/lib/storage";
import type { Asset, Criticality } from "@/lib/types";

export function AssetsView({
  assets,
  onChange,
}: {
  assets: Asset[];
  onChange: (assets: Asset[]) => SaveResult;
}) {
  const [name, setName] = useState("");
  const [keywords, setKeywords] = useState("");
  const [criticality, setCriticality] = useState<Criticality>("importante");
  const [note, setNote] = useState("");
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);

  function addAsset() {
    const parsed = keywords
      .split(",")
      .map((keyword) => keyword.trim())
      .filter((keyword) => keyword.length >= 3);
    if (name.trim().length < 2 || parsed.length === 0) {
      toast.error("Informe o nome e ao menos uma palavra-chave com 3 caracteres.");
      return;
    }
    const saved = onChange([
      {
        id: crypto.randomUUID(),
        name: name.trim(),
        keywords: parsed,
        criticality,
        note: note.trim(),
      },
      ...assets,
    ]);
    if (!saved.ok) {
      toast.error(saved.error);
      return;
    }
    setName("");
    setKeywords("");
    setNote("");
    toast.success("Ativo gravado neste navegador. A lista não vai para o GitHub.");
  }

  function changeCriticality(id: string, next: Criticality) {
    const saved = onChange(assets.map((asset) => (asset.id === id ? { ...asset, criticality: next } : asset)));
    if (!saved.ok) toast.error(saved.error);
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,18rem)_1fr]">
      <form
        className="space-y-3 rounded-lg border border-[#ddd4c4] bg-[#fffcf7] p-4"
        onSubmit={(event) => {
          event.preventDefault();
          addAsset();
        }}
      >
        <h2 className="font-serif text-xl">Novo ativo</h2>
        <div className="space-y-1.5">
          <Label htmlFor="asset-name">Nome</Label>
          <Input
            id="asset-name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="Firewall da borda"
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="asset-keywords">Palavras-chave</Label>
          <Input
            id="asset-keywords"
            value={keywords}
            onChange={(event) => setKeywords(event.target.value)}
            placeholder="fortios, fortigate"
          />
          <p className="text-xs text-[#6b6256]">
            Separadas por vírgula. A correspondência usa a frase inteira, então prefira o nome do produto.
          </p>
        </div>
        <div className="space-y-1.5">
          <Label>Criticidade</Label>
          <Select
            value={criticality}
            onValueChange={(value) => {
              if (value === "essencial" || value === "importante" || value === "apoio") {
                setCriticality(value);
              }
            }}
          >
            <SelectTrigger className="w-full">
              <SelectValue>{CRITICALITY_LABEL[criticality]}</SelectValue>
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="essencial">Essencial</SelectItem>
              <SelectItem value="importante">Importante</SelectItem>
              <SelectItem value="apoio">Apoio</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="asset-note">Nota</Label>
          <Textarea
            id="asset-note"
            value={note}
            onChange={(event) => setNote(event.target.value)}
            placeholder="Onde esse ativo vive"
          />
        </div>
        <Button type="submit">Adicionar</Button>
      </form>

      <div>
        <div className="mb-3 flex flex-col items-start gap-3 sm:flex-row sm:items-start sm:justify-between">
          <p className="text-sm text-[#5c564c]">
            Apague o que não existir no seu ambiente e inclua o que você opera. A lista fica neste navegador. Se você esvaziar, ela continua vazia até restaurar os exemplos.
          </p>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="shrink-0"
            onClick={() => {
              const saved = onChange(DEFAULT_ASSETS);
              if (saved.ok) toast.success("Lista de exemplo gravada neste navegador.");
              else toast.error(saved.error);
            }}
          >
            Restaurar exemplos
          </Button>
        </div>
        {assets.length === 0 ? (
          <p className="rounded-lg border border-dashed border-[#d3c8b4] px-4 py-8 text-sm text-[#5c564c]">
            Nenhum ativo. A correspondência fica parada até você cadastrar o primeiro.
          </p>
        ) : (
          <ul className="space-y-3">
            {assets.map((asset) => (
              <li key={asset.id} className="rounded-lg border border-[#ddd4c4] bg-[#fffcf7] px-4 py-3">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="font-medium">{asset.name}</p>
                    <div className="mt-2 max-w-40">
                      <Label className="sr-only" htmlFor={`asset-criticality-${asset.id}`}>
                        Criticidade de {asset.name}
                      </Label>
                      <Select
                        value={asset.criticality}
                        onValueChange={(value) => {
                          if (value === "essencial" || value === "importante" || value === "apoio") {
                            changeCriticality(asset.id, value);
                          }
                        }}
                      >
                        <SelectTrigger id={`asset-criticality-${asset.id}`} className="w-full">
                          <SelectValue>{CRITICALITY_LABEL[asset.criticality]}</SelectValue>
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="essencial">Essencial</SelectItem>
                          <SelectItem value="importante">Importante</SelectItem>
                          <SelectItem value="apoio">Apoio</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      if (pendingDelete !== asset.id) {
                        setPendingDelete(asset.id);
                        return;
                      }
                      const saved = onChange(assets.filter((item) => item.id !== asset.id));
                      if (!saved.ok) {
                        toast.error(saved.error);
                        return;
                      }
                      setPendingDelete(null);
                      toast.success("Ativo removido neste navegador.");
                    }}
                  >
                    {pendingDelete === asset.id ? "Confirmar remoção" : "Remover"}
                  </Button>
                </div>
                <p className="mt-2 text-sm text-[#3f382f]">{asset.keywords.join(" · ")}</p>
                {asset.note ? <p className="mt-1 text-sm text-[#5c564c]">{asset.note}</p> : null}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
