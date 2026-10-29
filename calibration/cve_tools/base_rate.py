"""Base rate: share of ALL plans that are priority at each vulnerable commit (cached worktrees)."""
import json, sys
from pathlib import Path as _P
_HERE = _P(__file__).resolve().parent.parent
sys.path.insert(0, str(_HERE)); sys.path.insert(0, str(_HERE.parent))
import cve_pairs as cp
from pathlib import Path
pairs = json.load(open(_HERE / "cve_pairs.json"))["pairs"]
cache = Path(sys.argv[1]); out = []
for p in pairs:
    tree = cp.checkout(cache, p["repo"], p["vulnerable"])
    led = cp.scan(tree, "python")
    pri = sum(1 for x in led["plans"] if (x.get("triage") or {}).get("priority"))
    by_sink = {}
    for x in led["plans"]:
        k = x["hypothesis"]["sink_node"]; d = by_sink.setdefault(k, [0, 0]); d[0] += 1; d[1] += bool((x.get("triage") or {}).get("priority"))
    out.append({"id": p["id"], "plans": len(led["plans"]), "priority": pri, "by_sink": by_sink})
    print(p["id"], len(led["plans"]), pri, flush=True)
json.dump(out, open(sys.argv[2], "w"), indent=1)
