import { appendFileSync } from "node:fs";

const SLOTS = [2, 8, 14, 20];
const OFFSET_MS = 3 * 60 * 60 * 1000;
const PUBLISHED_FEED = "https://avilarezende.github.io/ronda/feed.json";

export function latestSlotMs(now) {
  const local = new Date(now.getTime() - OFFSET_MS);
  const hour = local.getUTCHours();
  const slot = [...SLOTS].reverse().find((item) => item <= hour);
  const day = Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), local.getUTCDate());
  const dayMs = slot === undefined ? day - 24 * 60 * 60 * 1000 : day;
  return dayMs + ((slot ?? 20) + 3) * 60 * 60 * 1000;
}

async function main() {
  const event = process.env.GITHUB_EVENT_NAME ?? "push";
  let collect = true;
  if (event === "schedule") {
    const slot = latestSlotMs(new Date());
    try {
      const response = await fetch(PUBLISHED_FEED, { cache: "no-store" });
      if (!response.ok) throw new Error("feed");
      const body = await response.json();
      const fetched = Date.parse(body.fetchedAt);
      collect = !Number.isFinite(fetched) || fetched < slot;
    } catch {
      collect = true;
    }
  }
  const line = `collect=${collect ? "true" : "false"}\n`;
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, line);
  else process.stdout.write(line);
}

await main();
