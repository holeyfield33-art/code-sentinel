"""For each candidate fix commit, fetch the commit via the GitHub REST API (gh) and
record which modeled sink calls appear in removed/added Python lines, plus the
lines immediately around them. Cached per commit in diffs/."""
import json, re, subprocess, sys, concurrent.futures as cf
from pathlib import Path
cands = json.load(open(sys.argv[1])); cache = Path(sys.argv[2]); cache.mkdir(exist_ok=True)
SINK = re.compile(r"\b(yaml\.load|yaml\.unsafe_load|pickle\.loads?|os\.system|subprocess\.(run|call|check_call|check_output|Popen)|(?<![\w.])eval|(?<![\w.])exec|(?<![\w.])open|os\.open)\s*\(")
jobs = {}
for c in cands:
    for o, r, sha, _t in c["fix_refs"]:
        jobs[(o, r.removesuffix(".git"), sha)] = 1
    for repo, sha in c["git_fixed"]:
        m = re.match(r"https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", repo)
        if m and re.fullmatch(r"[0-9a-f]{40}", sha): jobs[(m.group(1), m.group(2), sha)] = 1
def fetch(key):
    o, r, sha = key
    p = cache / f"{o}__{r}__{sha}.json"
    if p.exists(): return key, json.loads(p.read_text())
    g = cache.parent / "git" / f"{o}__{r}"
    def git(*a, **k): return subprocess.run(["git", "-C", str(g), *a], capture_output=True, text=True, timeout=180, **k)
    try:
        if not g.exists():
            g.mkdir(parents=True); git("init", "-q"); git("remote", "add", "origin", f"https://github.com/{o}/{r}.git")
        f = git("fetch", "-q", "--depth=2", "--filter=blob:none", "origin", sha)
        if f.returncode: raise RuntimeError(f.stderr.strip()[-200:])
        full = git("rev-parse", "FETCH_HEAD").stdout.strip()
        parents = git("rev-list", "--parents", "-n1", full).stdout.split()[1:]
        msg = git("log", "-1", "--format=%cI%n%s", full).stdout.split("\n")
        files = []
        if parents:
            d = git("diff", "--unified=0", parents[0], full, "--", "*.py")
            cur = None
            for line in d.stdout.splitlines():
                if line.startswith("+++ "):
                    cur = {"file": line[6:], "removed_sinks": [], "added_sinks": [], "adds": 0, "dels": 0}
                    cur["test_file"] = bool(re.search(r"(^|/)tests?/|test_", cur["file"])); files.append(cur)
                elif cur and line.startswith("-") and not line.startswith("---"):
                    cur["dels"] += 1
                    if SINK.search(line): cur["removed_sinks"].append(line[1:].strip()[:200])
                elif cur and line.startswith("+"):
                    cur["adds"] += 1
                    if SINK.search(line): cur["added_sinks"].append(line[1:].strip()[:200])
        info = {"sha": full, "parents": parents, "date": msg[0], "msg": msg[1][:200] if len(msg) > 1 else "", "files": files}
    except Exception as exc:
        info = {"error": str(exc)[:200]}
    p.write_text(json.dumps(info)); return key, info
with cf.ThreadPoolExecutor(1) as ex:
    done = dict(ex.map(fetch, jobs))
ok = sum("error" not in v for v in done.values())
print(f"{len(jobs)} commits, fetched {ok}, errors {len(jobs)-ok}")
