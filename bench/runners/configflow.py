"""Runs ConfigFlow's subscription parser and Mihomo node converter on one file.

ConfigFlow converts share links by calling a Sub-Store service
(backend/utils/sub_store_client.py); with no such service running, link inputs
fail here. Clash YAML input is read by its own parser.
"""
import json, os, sys, time
import yaml

sys.path.insert(0, os.environ['CONFIGFLOW_REPO'])
from backend.utils.subscription_parser import parse_clash_yaml, parse_uri_list  # noqa: E402
from backend.converters.mihomo import convert_node_to_mihomo  # noqa: E402

inp, out = sys.argv[1], sys.argv[2]
raw = open(inp, encoding='utf-8', errors='replace').read()
t = time.perf_counter()
errs = []
try:
    nodes = parse_clash_yaml(raw) if 'proxies:' in raw else parse_uri_list(raw)
except Exception as e:  # noqa: BLE001
    nodes = []
    errs.append(str(e))
proxies = []
for n in nodes:
    try:
        proxies.append(convert_node_to_mihomo(n))
    except Exception as e:  # noqa: BLE001
        errs.append(f"{n.get('name')}: {e}")
ms = (time.perf_counter() - t) * 1000
print(json.dumps({'ms': ms, 'parsed': len(nodes), 'errors': errs[:10]}, ensure_ascii=False), file=sys.stderr)
if not proxies:
    sys.exit(1)
names = [p['name'] for p in proxies]
doc = {'mixed-port': 7890, 'proxies': proxies,
       'proxy-groups': [{'name': 'PROXY', 'type': 'select', 'proxies': names}], 'rules': ['MATCH,PROXY']}
yaml.safe_dump(doc, open(out, 'w'), allow_unicode=True, sort_keys=False)
