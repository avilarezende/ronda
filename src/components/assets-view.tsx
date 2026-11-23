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
import type { Asset, Criticality } from "@/lib/types";

export function AssetsView({
  assets,
  onChange,
}: {
  assets: Asset[];
  onChange: (assets: Asset[]) => void;
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
    onChange([
      {
        id: crypto.randomUUID(),
        name: name.trim(),
        keywords: parsed,
        criticality,
        note: note.trim(),
      },
      ...assets,
    ]);
    setName("");
    setKeywords("");
    setNote("");
    toast.success("Ativo incluído na correspondência.");
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
        <div className="mb-3 flex items-center justify-between gap-3">
          <p className="text-sm text-[#5c564c]">
            Ponto de partida para um ambiente de tribunal e de rede acadêmica. Apague o que não existir e inclua o que você opera.
          </p>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => {
              onChange(DEFAULT_ASSETS);
              toast.success("Lista de exemplo restaurada.");
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
                    <p className="text-xs text-[#6b6256]">{CRITICALITY_LABEL[asset.criticality]}</p>
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
                      onChange(assets.filter((item) => item.id !== asset.id));
                      setPendingDelete(null);
                      toast.success("Ativo removido.");
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
