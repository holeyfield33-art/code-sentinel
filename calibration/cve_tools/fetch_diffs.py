"""For each candidate fix commit, shallow-fetch the commit and its parent with git and
record which modeled sink calls appear in removed/added Python lines. Removed lines
keep their line number in the parent file. Cached per commit in the given directory."""
import json, os, re, subprocess, sys, concurrent.futures as cf
from pathlib import Path
cands = json.load(open(sys.argv[1])); cache = Path(sys.argv[2]); cache.mkdir(exist_ok=True)
SINK = re.compile(r"\b(yaml\.load|yaml\.unsafe_load|pickle\.loads?|os\.system|subprocess\.(run|call|check_call|check_output|Popen)|(?<![\w.])eval|(?<![\w.])exec|(?<![\w.])open|os\.open)\s*\(")
# Overridable so tests can point at a local repository; real runs use GitHub.
GIT_BASE = os.environ.get("SZ_GIT_BASE", "https://github.com").rstrip("/")
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
            g.mkdir(parents=True); git("init", "-q"); git("remote", "add", "origin", f"{GIT_BASE}/{o}/{r}.git")
        f = git("fetch", "-q", "--depth=2", "--filter=blob:none", "origin", sha)
        if f.returncode: raise RuntimeError(f.stderr.strip()[-200:])
        full = git("rev-parse", "FETCH_HEAD").stdout.strip()
        parents = git("rev-list", "--parents", "-n1", full).stdout.split()[1:]
        msg = git("log", "-1", "--format=%cI%n%s", full).stdout.split("\n")
        files = []
        if parents:
            d = git("diff", "--unified=0", parents[0], full, "--", "*.py")
            cur, old_no, old_path = None, 0, None
            hunk = re.compile(r"^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@")
            for line in d.stdout.splitlines():
                if line.startswith(("--- a/", "--- /dev/null")):
                    # The vulnerable site lives at the parent, so keep the OLD path.
                    old_path = line[6:] if line.startswith("--- a/") else None
                elif line.startswith(("+++ b/", "+++ /dev/null")):
                    path = old_path or line[6:]
                    cur = {"file": path, "removed_sinks": [], "added_sinks": [], "adds": 0, "dels": 0,
                           "test_file": bool(re.search(r"(^|/)tests?/|test_", path)),
                           "deleted": line.startswith("+++ /dev/null")}
                    files.append(cur)
                elif cur and line.startswith("@@"):
                    m = hunk.match(line)
                    old_no = int(m.group(1)) if m else 0
                elif cur and line.startswith("-"):
                    cur["dels"] += 1
                    if SINK.search(line):
                        # Position in the parent file, so the site is located exactly, not by text search.
                        cur["removed_sinks"].append({"text": line[1:].strip()[:200], "old_lineno": old_no})
                    old_no += 1
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
