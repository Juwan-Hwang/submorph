#!/usr/bin/env python3
"""Runs submorph and the competitors on every sample, for both targets.

STATUS: work in progress. The runners and the run phase are written but have
not completed a full pass yet; bench/score.py (scoring against the truth files
and loading every output in sing-box 1.12 / 1.14 and mihomo) is not written.
See docs/progress.md.

  python3 bench/run.py            build submorph, run offline and online, score
  python3 bench/run.py --phase run --mode offline   (used internally)
  python3 bench/run.py --phase score                score existing outputs

The offline run happens in a network namespace with only loopback
(`sudo unshare -n`), so a tool that needs the internet shows it in the results.
Outputs: bench/out/<mode>/<tool>/<sample>.<target>.{out,err,meta.json}.
"""
import argparse, json, os, shutil, signal, statistics, subprocess, sys, time, urllib.parse, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONV = os.environ.get('CONVERTERS') or os.path.join(os.path.dirname(os.path.dirname(HERE)), 'converters')
CACHE = os.path.join(HERE, 'runners', '.cache')
SAMPLES = os.path.join(HERE, 'samples')
OUT = os.path.join(HERE, 'out')
SUBMORPH = os.path.join(ROOT, 'target', 'release', 'submorph')
NODE_PATH = os.path.join(CONV, 'sub-store-org_Sub-Store', 'backend', 'node_modules')

CONTENT_SAMPLES = ['full.yaml', 'full.json', 'links.txt', 'links.b64', 'singbox.json', 'messy.yaml']
ERROR_SAMPLES = sorted(os.listdir(os.path.join(SAMPLES, 'errors'))) if os.path.isdir(os.path.join(SAMPLES, 'errors')) else []
LARGE_SAMPLES = ['large.yaml', 'large.b64']
TARGETS = ['mihomo', 'sing-box']

SC_PORTS = {'subconverter-tindy': 25501, 'subconverter-asd': 25502, 'subconverter-mcx': 25503}
SC_DIRS = {'subconverter-tindy': 'sc-tindy', 'subconverter-asd': 'sc-asd', 'subconverter-mcx': 'sc-mcx'}

# tool -> target -> how it is asked for that target (None: not offered)
TOOLS = {
    'submorph': {'mihomo': 'mihomo', 'sing-box': 'sing-box'},
    'sub-store': {'mihomo': 'mihomo', 'sing-box': 'sing-box'},
    'sublink-worker': {'mihomo': 'clash', 'sing-box': 'sing-box'},
    'subconverter-tindy': {'mihomo': 'clash', 'sing-box': None},
    'subconverter-asd': {'mihomo': 'clash', 'sing-box': 'singbox'},
    'subconverter-mcx': {'mihomo': 'clash', 'sing-box': 'singbox'},
    'subboost': {'mihomo': 'mihomo', 'sing-box': None},
    'configflow': {'mihomo': 'mihomo', 'sing-box': None},
}
TOOL_INFO = {
    'submorph': 'this project',
    'sub-store': 'Sub-Store 2.44.18 proxy-utils (also the core of SubCase, and what ConfigFlow calls for links)',
    'sublink-worker': 'Sublink Worker (sublink-worker builders; also deployed at sub.haitunt.org)',
    'subconverter-tindy': 'subconverter v0.9.0 release, tindy2013 (backend of sub-web.wcc.best)',
    'subconverter-asd': 'subconverter v0.9.9, asdlokj1qpi233 fork (the active fork; sub-web style sites such as sub.v1.mk, amyconvert.com, sublink.dev run subconverter backends)',
    'subconverter-mcx': 'subconverter v0.9.2 (reports v0.9.1-mihomo), MetaCubeX fork',
    'subboost': 'SubBoost @subboost/core parser and Clash generator',
    'configflow': 'ConfigFlow backend parser and Mihomo node converter',
}


def timed(cmd, env=None, timeout=300, stdin=None):
    """Runs cmd under /usr/bin/time; returns rc, stdout, stderr, seconds, max RSS in KiB."""
    tf = '/tmp/_bench_time'
    full = ['/usr/bin/time', '-f', '%e %M', '-o', tf] + cmd
    try:
        r = subprocess.run(full, capture_output=True, env=env, timeout=timeout, stdin=stdin)
        rc, out, err = r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, b'', b'timeout', float(timeout), 0
    try:
        last = open(tf).read().strip().splitlines()[-1].split()
        secs, rss = float(last[0]), int(last[1])
    except Exception:  # noqa: BLE001
        secs, rss = 0.0, 0
    return rc, out, err, secs, rss


def node_env():
    e = dict(os.environ)
    e['NODE_PATH'] = NODE_PATH
    e['SUBLINK_REPO'] = os.path.join(CONV, '7Sageer_sublink-worker')
    e['CONFIGFLOW_REPO'] = os.path.join(CONV, 'thsrite_configflow')
    return e


# --------------------------------------------------------------- subconverter
class SubconverterServers:
    def __init__(self):
        self.procs = {}

    def start(self, tool):
        d = os.path.join(CACHE, SC_DIRS[tool])
        p = subprocess.Popen(['./subconverter'], cwd=d, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        self.procs[tool] = p
        for _ in range(100):
            try:
                urllib.request.urlopen(f'http://127.0.0.1:{SC_PORTS[tool]}/version', timeout=1).read()
                return
            except Exception:  # noqa: BLE001
                time.sleep(0.1)

    def stop(self, tool):
        p = self.procs.pop(tool, None)
        if p:
            os.killpg(p.pid, signal.SIGTERM)
            p.wait()

    def hwm_kib(self, tool):
        p = self.procs.get(tool)
        for line in open(f'/proc/{p.pid}/status'):
            if line.startswith('VmHWM'):
                return int(line.split()[1])
        return 0

    def stop_all(self):
        for t in list(self.procs):
            self.stop(t)


def sc_url_param(path):
    # A sub-web front end sends pasted links joined by '|'; a subscription
    # (file or Base64) is passed as its location.
    if path.endswith('links.txt'):
        return '|'.join(l.strip() for l in open(path) if l.strip())
    return path


def run_one(tool, target_arg, path, out_path, servers):
    """Returns dict(rc, seconds, rss_kib, stderr) and writes out_path."""
    env = node_env()
    if tool == 'submorph':
        rc, _, err, s, m = timed([SUBMORPH, '-t', target_arg, '--diagnostics', 'text', '-o', out_path, path])
    elif tool == 'sub-store':
        rc, _, err, s, m = timed(['node', os.path.join(CACHE, 'substore.cjs'), path, target_arg, out_path], env=env)
    elif tool == 'sublink-worker':
        rc, _, err, s, m = timed(['node', os.path.join(HERE, 'runners', 'sublink.mjs'), path, 'sing-box' if target_arg == 'sing-box' else 'clash', out_path], env=env)
    elif tool == 'subboost':
        rc, _, err, s, m = timed(['node', os.path.join(CACHE, 'subboost.cjs'), path, out_path], env=env)
    elif tool == 'configflow':
        rc, _, err, s, m = timed([os.path.join(CACHE, 'cfvenv', 'bin', 'python'), os.path.join(HERE, 'runners', 'configflow.py'), path, out_path], env=env)
    elif tool.startswith('subconverter'):
        q = urllib.parse.urlencode({'target': target_arg, 'url': sc_url_param(path)})
        url = f'http://127.0.0.1:{SC_PORTS[tool]}/sub?{q}'
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(url, timeout=120) as r:
                body, rc = r.read(), 0
        except urllib.error.HTTPError as e:
            body, rc = e.read(), e.code
        except Exception as e:  # noqa: BLE001
            body, rc = str(e).encode(), 1
        s = time.perf_counter() - t0
        m = servers.hwm_kib(tool)
        if rc == 0:
            open(out_path, 'wb').write(body)
            err = b''
        else:
            err = f'HTTP {rc}: '.encode() + body[:2000]
    else:
        raise ValueError(tool)
    if rc != 0 and os.path.exists(out_path) and tool != 'submorph':
        pass
    return {'rc': rc, 'seconds': s, 'rss_kib': m, 'stderr': err.decode('utf-8', 'replace')[-6000:]}


def phase_run(mode):
    base = os.path.join(OUT, mode)
    shutil.rmtree(base, ignore_errors=True)
    servers = SubconverterServers()
    for t in SC_PORTS:
        servers.start(t)
    try:
        jobs = [(s, os.path.join(SAMPLES, s)) for s in CONTENT_SAMPLES] + [('errors/' + s, os.path.join(SAMPLES, 'errors', s)) for s in ERROR_SAMPLES]
        for tool, targets in TOOLS.items():
            d = os.path.join(base, tool)
            os.makedirs(os.path.join(d, 'errors'), exist_ok=True)
            for sname, path in jobs:
                for target, arg in targets.items():
                    if arg is None or (sname.startswith('errors/') and target != 'mihomo' and tool != 'submorph'):
                        continue
                    stem = os.path.join(d, f'{sname}.{target}')
                    res = run_one(tool, arg, path, stem + '.out', servers)
                    open(stem + '.err', 'w').write(res.pop('stderr'))
                    json.dump(res, open(stem + '.meta.json', 'w'))
        if mode == 'offline':
            speed = {}
            for tool, targets in TOOLS.items():
                for sname in LARGE_SAMPLES:
                    path = os.path.join(SAMPLES, sname)
                    for target, arg in targets.items():
                        if arg is None:
                            continue
                        runs = []
                        for i in range(3):
                            if tool in SC_PORTS:
                                servers.stop(tool)
                                servers.start(tool)
                            out_path = os.path.join(base, tool, f'{sname}.{target}.out')
                            res = run_one(tool, arg, path, out_path, servers)
                            runs.append(res)
                        ok = [r for r in runs if r['rc'] == 0]
                        speed[f'{tool}|{sname}|{target}'] = {
                            'ok': len(ok) == 3,
                            'seconds': statistics.median(r['seconds'] for r in runs),
                            'rss_kib': max(r['rss_kib'] for r in runs),
                            'error': '' if ok else runs[0]['stderr'][-300:],
                            'how': 'HTTP request to a running server; RSS is the server peak' if tool in SC_PORTS else 'whole process, from start to exit',
                        }
            json.dump(speed, open(os.path.join(base, 'speed.json'), 'w'), indent=1)
    finally:
        servers.stop_all()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--phase', choices=['all', 'run', 'score'], default='all')
    ap.add_argument('--mode', choices=['offline', 'online'], default='offline')
    a = ap.parse_args()
    if a.phase == 'run':
        phase_run(a.mode)
        return
    if a.phase == 'all':
        subprocess.run(['cargo', 'build', '--release', '--quiet'], cwd=ROOT, check=True)
        subprocess.run([sys.executable, os.path.join(HERE, 'make_samples.py')], check=True)
        user = os.environ.get('USER') or subprocess.run(['id', '-un'], capture_output=True, text=True).stdout.strip()
        inner = f'ip link set lo up && exec sudo -E -u {user} env PATH="$PATH" {sys.executable} {os.path.abspath(__file__)} --phase run --mode offline'
        subprocess.run(['sudo', '-E', 'unshare', '-n', '--', 'bash', '-c', inner], check=True)
        phase_run('online')
    try:
        import score  # noqa: E402  (bench/score.py, not written yet)
    except ImportError:
        sys.exit('bench/score.py is not written yet; raw outputs are in bench/out/. See docs/progress.md.')
    score.main()


if __name__ == '__main__':
    sys.path.insert(0, HERE)
    main()
