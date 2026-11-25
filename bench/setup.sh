#!/usr/bin/env bash
# Prepares the competitors for bench/run.py. Everything runs locally: this
# script only builds or copies code that is already on disk, plus the npm/pip
# packages and release binaries it needs. No subscription leaves the machine.
#
# CONVERTERS points at the directory holding the competitors' sources and
# the core binaries (bin/sing-box-1.12.12, bin/sing-box (1.14.x), bin/mihomo,
# bin/sc-asd, bin/sc-tindy, bin/sc-mcx). Default: ../converters next to the
# repository.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CONV="${CONVERTERS:-$(cd "$HERE/../.." && pwd)/converters}"
CACHE="$HERE/runners/.cache"
mkdir -p "$CACHE"

# Sub-Store (AGPL): bundle its proxy-utils into one script. Not copied into
# this repository; the bundle lives in the git-ignored cache.
SS="$CONV/sub-store-org_Sub-Store/backend"
(cd "$SS" && [ -d node_modules/dotenv ] || npx -y pnpm@11 install --ignore-scripts)
(cd "$SS" && node -e "
require('esbuild').build({entryPoints:['$HERE/runners/substore-entry.js'],bundle:true,platform:'node',
 outfile:'$CACHE/substore.cjs',alias:{'@':'./src'},logLevel:'error'}).then(()=>console.log('Sub-Store bundled'))")

# SubBoost (AGPL): bundle @subboost/core's parser and generator.
mkdir -p "$CACHE/subboost-deps"
(cd "$CACHE/subboost-deps" && [ -d node_modules/js-yaml ] || { npm init -y >/dev/null; npm i js-yaml@5 peggy@5 safe-regex2@5 esbuild >/dev/null; })
(cd "$CACHE/subboost-deps" && node -e "
require('esbuild').build({entryPoints:['$HERE/runners/subboost-entry.ts'],bundle:true,platform:'node',format:'cjs',
 outfile:'$CACHE/subboost.cjs',alias:{'@subboost/core':'$CONV/SubBoost_subboost/packages/core/src'},
 nodePaths:['$CACHE/subboost-deps/node_modules'],logLevel:'error'}).then(()=>console.log('SubBoost bundled'))")

# ConfigFlow (MIT, Python): a venv with its requirements.
[ -x "$CACHE/cfvenv/bin/python" ] || { python3 -m venv "$CACHE/cfvenv"; "$CACHE/cfvenv/bin/pip" install -q -r "$CONV/thsrite_configflow/backend/requirements.txt"; }

# subconverter release builds: tindy2013 v0.9.0, asdlokj1qpi233 v0.9.9,
# MetaCubeX v0.9.2. Each gets its own copy and port so they can run side by side.
port=25501
for fork in sc-tindy sc-asd sc-mcx; do
  src="$CONV/bin/$fork/subconverter"
  dst="$CACHE/$fork"
  if [ ! -d "$dst" ]; then
    cp -r "$src" "$dst"
    [ -f "$dst/pref.toml" ] || cp "$dst/pref.example.toml" "$dst/pref.toml"
  fi
  sed -i -E "s/^port = [0-9]+/port = $port/; s/^listen = .*/listen = \"127.0.0.1\"/" "$dst/pref.toml"
  port=$((port + 1))
done
echo "setup done"
