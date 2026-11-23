import { spawn } from "node:child_process";
import { rename } from "node:fs/promises";
import path from "node:path";

const root = process.cwd();
const api = path.join(root, "src/app/api");
const stash = path.join(root, ".pages-api");

function run(command, args, env, omit = []) {
  const merged = { ...process.env, ...env };
  for (const name of omit) delete merged[name];
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: "inherit",
      env: merged,
    });
    child.on("exit", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`${command} encerrou com código ${code ?? "desconhecido"}`));
    });
  });
}

const basePath = process.env.BASE_PATH ?? "";
await rename(api, stash);
try {
  await run("npx", ["tsx", "scripts/write-feed.ts"], {});
  await run(
    "npx",
    ["next", "build"],
    {
      NEXT_PUBLIC_STATIC: "1",
      BASE_PATH: basePath,
      NEXT_PUBLIC_BASE_PATH: basePath,
    },
    ["VULDB_API_KEY"],
  );
} finally {
  await rename(stash, api);
}
