"""Inventory: PyPA advisories whose text names a sink Sentinel-Zero models and that
point at a GitHub fix commit. Output: candidates.json (no network)."""
import json, re, sys
from pathlib import Path
import yaml
root = Path(sys.argv[1])
PAT = {
 "DESERIALIZATION": r"yaml\.load\b|pickle\.loads?\b|\bunpickl|yaml\.unsafe_load|FullLoader|yaml\.Loader",
 "PROCESS_EXEC": r"os\.system|subprocess|shell\s*=\s*True|\beval\(|\bexec\(|\beval\b|command injection|os command",
 "FILE_IO": r"path traversal|directory traversal|\bopen\(|arbitrary file (read|write)",
}
COMMIT = re.compile(r"https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})")
out = []
for f in root.glob("vulns/*/*.yaml"):
    try: d = yaml.safe_load(f.read_text())
    except Exception: continue
    text = " ".join(str(d.get(k, "")) for k in ("summary", "details"))
    kinds = [k for k, p in PAT.items() if re.search(p, text, re.I)]
    if not kinds: continue
    fixes = set()
    for r in d.get("references", []) or []:
        m = COMMIT.search(r.get("url", ""))
        if m: fixes.add((m.group(1), m.group(2), m.group(3), r.get("type")))
    repo_events = []
    for a in d.get("affected", []) or []:
        for rg in a.get("ranges", []) or []:
            if rg.get("type") == "GIT" and "github.com" in rg.get("repo", ""):
                for ev in rg.get("events", []):
                    if "fixed" in ev: repo_events.append((rg["repo"], ev["fixed"]))
    if not fixes and not repo_events: continue
    out.append({"id": d.get("id"), "aliases": d.get("aliases", []), "package": f.parent.name, "kinds": kinds,
                "fix_refs": sorted(fixes), "git_fixed": repo_events, "text": text[:400]})
json.dump(out, open(sys.argv[2], "w"), indent=1)
from collections import Counter
print(len(out), "candidates;", Counter(k for o in out for k in o["kinds"]))
