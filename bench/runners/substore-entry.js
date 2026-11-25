// Runs Sub-Store's own parser and producer on one file (bundled by setup.sh).
import { ProxyUtils } from '@/core/proxy-utils';
import fs from 'fs';

const [, , input, target, out] = process.argv;
const raw = fs.readFileSync(input, 'utf8');
const t0 = process.hrtime.bigint();
const proxies = ProxyUtils.parse(raw);
const res = ProxyUtils.produce(proxies, target);
const ms = Number(process.hrtime.bigint() - t0) / 1e6;
fs.writeFileSync(out, typeof res === 'string' ? res : JSON.stringify(res, null, 1));
console.error(JSON.stringify({ ms, parsed: proxies.length }));
