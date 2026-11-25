// Runs Sublink Worker's config builders (MIT) on one file, no service involved.
// Uses the builders exactly as its worker does, with its default "balanced"
// rule selection, since it has no option to keep the input's own rules.
import fs from 'node:fs';
import path from 'node:path';

const repo = process.env.SUBLINK_REPO;
const [, , input, target, out] = process.argv;
const text = fs.readFileSync(input, 'utf8');
const { PREDEFINED_RULE_SETS } = await import(path.join(repo, 'src/config/index.js'));
const rules = PREDEFINED_RULE_SETS.balanced;
const t0 = process.hrtime.bigint();
let result;
if (target === 'sing-box') {
  const { SingboxConfigBuilder } = await import(path.join(repo, 'src/builders/SingboxConfigBuilder.js'));
  const b = new SingboxConfigBuilder(text, rules, [], undefined, 'zh-CN', 'bench', false, false, undefined, undefined, '1.12', true);
  await b.build();
  result = JSON.stringify(b.config, null, 1);
} else {
  const { ClashConfigBuilder } = await import(path.join(repo, 'src/builders/ClashConfigBuilder.js'));
  const b = new ClashConfigBuilder(text, rules, [], undefined, 'zh-CN', 'bench', false, false, undefined, undefined, true);
  const y = await b.build();
  result = typeof y === 'string' ? y : JSON.stringify(b.config);
}
const ms = Number(process.hrtime.bigint() - t0) / 1e6;
fs.writeFileSync(out, result);
console.error(JSON.stringify({ ms }));
