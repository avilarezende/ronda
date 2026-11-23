import { spawn } from "node:child_process";
import { rename } from "node:fs/promises";
import path from "node:path";

const root = process.cwd();
const api = path.join(root, "src/app/api");
const stash = path.join(root, ".pages-api");

function run(command, args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: "inherit",
      env: { ...process.env, ...env },
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
  await run("npx", ["next", "build"], {
    NEXT_PUBLIC_STATIC: "1",
    BASE_PATH: basePath,
    NEXT_PUBLIC_BASE_PATH: basePath,
  });
} finally {
  await rename(stash, api);
}
