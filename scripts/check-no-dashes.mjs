import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const ROOT = process.cwd();
const SKIP = new Set(["node_modules", ".git", "dist", "coverage", ".wrangler", ".tri"]);
const TEXT = /\.(md|ts|mts|js|mjs|json|jsonc|yaml|yml|txt|toml)$/;
const BAD = /[\u2013\u2014]/;

function walk(dir, out) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (TEXT.test(name)) out.push(full);
  }
  return out;
}

let failures = 0;
for (const file of walk(ROOT, [])) {
  const lines = readFileSync(file, "utf8").split("\n");
  lines.forEach((line, i) => {
    if (BAD.test(line)) {
      failures++;
      console.error(`${relative(ROOT, file)}:${i + 1}: em or en dash found`);
    }
  });
}
if (failures > 0) {
  console.error(`${failures} line(s) contain em or en dashes`);
  process.exit(1);
}
console.log("no em or en dashes");
