"""Turn fetched fix diffs into scoreable pairs, with no hand-picking.

Usage: select_pairs.py candidates.json DIFF_DIR OUT_MANIFEST.json ADVISORY_DB_COMMIT

A pair qualifies when its fix commit, in a non-test .py file, removes or rewrites
a line calling one of Sentinel-Zero's modeled Python sinks (a "sink-line fix",
such as yaml.load -> yaml.safe_load or shell=True -> an argument list). The
vulnerable site is located by parsing the file at the parent commit: the
enclosing function of that line, and the sink identity spelled on it.

Fixes that add a guard without touching the sink line (typical for path traversal)
are counted and listed, but not scored in this first version: their site cannot be
read off the diff without guessing.
"""
import ast, json, re, subprocess, sys
from collections import Counter
from pathlib import Path

cands = json.load(open(sys.argv[1])); diffs = Path(sys.argv[2]); gitroot = diffs.parent / "git"
MAX_PY_FILES = 3000
SINKS = [  # spelled-call regex -> sink identity in Sentinel-Zero's table
    (r"\byaml\.(load|unsafe_load)\s*\(", "yaml.load"),
    (r"\bpickle\.loads\s*\(", "pickle.loads"), (r"\bpickle\.load\s*\(", "pickle.load"),
    (r"\bos\.system\s*\(", "os.system"),
    (r"\bsubprocess\.(run|call|check_call|check_output|Popen)\s*\(", None),
    (r"(?<![\w.])eval\s*\(", "builtins.eval"), (r"(?<![\w.])exec\s*\(", "builtins.exec"),
    (r"(?<![\w.])open\s*\(", "builtins.open"), (r"\bos\.open\s*\(", "os.open"),
]


def sink_of(line):
    for pat, ident in SINKS:
        m = re.search(pat, line)
        if m:
            return ident or f"subprocess.{m.group(1)}"
    return None


def git(g, *a):
    r = subprocess.run(["git", "-C", str(g), *a], capture_output=True, text=True, timeout=300)
    return r.stdout if r.returncode == 0 else None


def enclosing(tree, lineno):
    best = None
    def visit(node, prefix):
        nonlocal best
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = f"{prefix}.{child.name}" if prefix else child.name
                if child.lineno <= lineno <= (child.end_lineno or child.lineno):
                    if not isinstance(child, ast.ClassDef):
                        best = name
                    visit(child, name)
    visit(tree, "")
    return best


def real_call(tree, lineno, ident):
    """A Call node to the sink starts on this line (not a comment or a string)."""
    want = ident.split(".")[-1]
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.lineno <= lineno <= (node.end_lineno or node.lineno):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            if name == want and node.lineno == lineno:
                return True
    return False


pairs, guard_only, skipped = [], [], Counter()
seen_repo = set()
by_id = {}
for c in cands:
    for o, r, sha, _t in c["fix_refs"]:
        by_id.setdefault((o, r.removesuffix(".git"), sha), c)
for f in sorted(diffs.glob("*.json")):
    o, r, sha = f.stem.split("__")
    d = json.loads(f.read_text()); c = by_id.get((o, r, sha))
    if c is None:
        c = next((x for x in cands if any(sha == s for _repo, s in x["git_fixed"])), None)
    if "error" in d or not d.get("parents") or c is None:
        skipped["fetch_error_or_root"] += 1; continue
    src = [x for x in d["files"] if not x["test_file"] and not re.search(r"(^|/)tests?/|(^|/)test_[^/]*$|_tests?\.py$|(^|/)conftest\.py$", x["file"])]
    # A file the fix deleted is a removal, not a fix: "gone" afterwards would be trivially
    # true, and the code may not be the advisory's vulnerability at all.
    deleted = sum(len(x["removed_sinks"]) for x in src if x.get("deleted"))
    if deleted:
        skipped["sink_calls_in_deleted_files"] += deleted
    changed = [(x["file"], rem["text"], rem["old_lineno"]) for x in src if not x.get("deleted")
               for rem in x["removed_sinks"] if sink_of(rem["text"])]
    if not changed:
        if src:
            guard_only.append({"id": c["id"], "repo": f"{o}/{r}", "fix": sha, "kinds": c["kinds"]})
        skipped["no_sink_line_in_fix" if src else "no_python_source_change"] += 1; continue
    g = gitroot / f"{o}__{r}"; parent = d["parents"][0]
    git(g, "fetch", "-q", "--depth=1", "--filter=blob:none", "origin", parent)
    count = (git(g, "ls-tree", "-r", "--name-only", parent) or "").count(".py\n")
    if count > MAX_PY_FILES:
        skipped["repo_too_large"] += 1; continue
    sites = []
    for path, line, i in changed:
        text = git(g, "show", f"{parent}:{path}")
        if text is None: continue
        try: tree = ast.parse(text)
        except SyntaxError: continue
        lines = text.splitlines()
        # Locate the removed call by its position in the parent file, never by text search:
        # the same call text can appear in several functions.
        if not 1 <= i <= len(lines) or lines[i - 1].strip()[:200] != line:
            skipped["diff_position_mismatch"] += 1; continue
        func = enclosing(tree, i)
        ident = sink_of(line)
        family = "DESERIALIZATION" if ident.startswith(("yaml", "pickle")) else (
            "FILE_IO" if ident in ("builtins.open", "os.open") else "PROCESS_EXEC")
        if func and real_call(tree, i, ident) and family in c["kinds"] and not re.search(r"Test", func.split(".")[0]):
            site = {"file": path, "function": func, "sink": ident, "line_at_vulnerable": i, "line": line.strip()[:160]}
            if site not in sites: sites.append(site)
    if not sites:
        skipped["site_not_in_a_function"] += 1; continue
    key = (o.lower(), r.lower())
    if key in seen_repo:
        skipped["second_pair_same_repo"] += 1; continue
    seen_repo.add(key)
    pairs.append({"id": c["id"], "aliases": c.get("aliases", []), "package": c["package"],
                  "repo": f"https://github.com/{o}/{r}", "vulnerable": parent, "fixed": d["sha"],
                  "language": "python", "kind": sorted({s["sink"].split(".")[0] for s in sites}) and
                  ("DESERIALIZATION" if any(s["sink"].startswith(("yaml", "pickle")) for s in sites) else
                   "FILE_IO" if any("open" in s["sink"] for s in sites) else "PROCESS_EXEC"),
                  "py_files": count, "sites": sites, "fix_message": d.get("msg", "")})
advisory_commit = sys.argv[4] if len(sys.argv) > 4 else "unknown"
fix_commits = len(list(diffs.glob("*.json")))
fetched = sum("error" not in json.loads(p.read_text()) for p in diffs.glob("*.json"))
manifest = {
    "schema": "sentinel-cve-pairs-v1",
    "source": {"database": "https://github.com/pypa/advisory-database", "commit": advisory_commit,
               "selection": "calibration/cve_tools/ (scan_advisories.py -> fetch_diffs.py -> select_pairs.py); no hand-picking",
               "rule": "fix commit removes or rewrites a call to a modeled Python sink in non-test source; site = the "
                       "enclosing function of that call, located by its line in the parent commit; sink family must "
                       "match the advisory text; calls in files the fix deleted are not scored; one pair per repository; "
                       "repos up to 3000 .py files"},
    "inventory": {"advisories_matched_by_text": len(cands), "fix_commits": fix_commits, "fix_commits_fetched": fetched,
                  "pairs": len(pairs), "guard_only_fixes_not_scored": len(guard_only)},
    "pairs": [{k: p[k] for k in ("id", "aliases", "package", "repo", "vulnerable", "fixed", "language", "kind",
                                 "sites", "fix_message")} for p in pairs],
    "guard_only_fixes": guard_only,
}
json.dump(manifest, open(sys.argv[3], "w"), indent=1)
print(len(pairs), "pairs;", Counter(p["kind"] for p in pairs), "| guard-only fixes:", len(guard_only), "| skipped:", dict(skipped))
