// Runs SubBoost's parser and Clash generator on one file (bundled by setup.sh).
import { parseSubscription } from "@subboost/core/parser";
import { generateClashYaml } from "@subboost/core/generator";
import fs from "node:fs";

const [, , input, out] = process.argv;
const raw = fs.readFileSync(input, "utf8");
const t0 = process.hrtime.bigint();
const r = parseSubscription(raw);
if (!r.nodes.length) {
  console.error(JSON.stringify({ parsed: 0, errors: r.errors }));
  process.exit(1);
}
const y = generateClashYaml({ nodes: r.nodes });
const ms = Number(process.hrtime.bigint() - t0) / 1e6;
fs.writeFileSync(out, y);
console.error(JSON.stringify({ ms, parsed: r.nodes.length, errors: r.errors }));
