import { mkdir, writeFile } from "node:fs/promises";
import { clearFeedCache, loadFeed } from "@/lib/feeds";

async function main() {
  clearFeedCache();
  const body = await loadFeed(true);
  const coreDown = body.sources.filter((source) => source.id !== "certbr").every((source) => !source.ok);
  if (coreDown || body.vulnerabilities.length === 0) {
    console.error("As fontes principais não responderam. A página publicada permanece na coleta anterior.");
    process.exit(1);
  }

  await mkdir("public", { recursive: true });
  await writeFile("public/feed.json", JSON.stringify(body));
  for (const source of body.sources) {
    console.log(`${source.label}: ${source.ok ? String(source.count) : (source.error ?? "falhou")}`);
  }
  console.log(`Coleta com ${body.vulnerabilities.length} itens. Próxima atualização: ${body.nextUpdate}`);
}

main().catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});
