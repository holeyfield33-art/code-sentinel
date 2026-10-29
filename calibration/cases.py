"""Labeled calibration fixtures for Sentinel-Zero's triage.

Each case is a tiny program whose correct triage is known before any scan:

  reachable     a sink an attacker can influence, unguarded, in production
                code. Correct triage: a plan that IS priority.
  near_miss     the same kind of sink made safe or low-value by exactly one
                thing (a real guard, constant arguments, test/example code,
                a low-signal sink). Correct triage: a plan that is NOT
                priority.
  coverage_gap  a real sink the scanner is known not to model yet (dynamic
                dispatch, pathlib, network). Correct triage would be a
                priority plan; the scorer reports whether the miss is honest
                (an unresolved call is counted) or silent.

`pair` names the case that differs by one change, so a regression can be
read as "the rule for <dimension> broke", not "the number went down".

Cases are hand-written, generic Python idioms, not copied from any one
project, so the harness measures the rules rather than a codebase's style.
Add a case by appending to CASES; `calibrate.py materialize` re-pins digests.
"""
from __future__ import annotations

from dataclasses import dataclass, field


# expect_guard default: this case makes no claim about guarded_by.
UNCHECKED = "<unchecked>"


@dataclass(frozen=True)
class Case:
    id: str
    family: str  # reachable | near_miss | coverage_gap
    dimension: str  # which triage rule this exercises
    sink: str  # expected sink_node (qualified name) the case is about
    files: dict[str, str]
    pair: str | None = None
    # expected triage.guarded_by: a guard name, None for "must not be credited
    # with a guard", or UNCHECKED when the case is not about guards
    expect_guard: str | None = UNCHECKED
    expect_constant: bool | None = None  # expected triage.constant_arguments; None = not checked
    note: str = ""
    tags: tuple[str, ...] = field(default=())


VALIDATOR = "def is_safe_name(value):\n    return value.isalnum()\n\n\n"
RAISING_VALIDATOR = (
    "def require_safe_name(value):\n"
    "    if not value.isalnum():\n"
    "        raise ValueError(value)\n\n\n"
)


def app(body: str, header: str = "import subprocess\n\n\n") -> dict[str, str]:
    return {"app.py": header + body}


CASES: list[Case] = [
    # --- baselines: plain reachable sinks, one per sink family ------------------
    Case("base-subprocess", "reachable", "baseline", "subprocess.run",
         app("def run(cmd):\n    return subprocess.run(cmd, shell=True)\n")),
    Case("base-os-system", "reachable", "baseline", "os.system",
         app("def run(cmd):\n    return os.system(cmd)\n", "import os\n\n\n")),
    Case("base-open", "reachable", "baseline", "builtins.open",
         app("def read(path):\n    with open(path) as handle:\n        return handle.read()\n", "")),
    Case("base-pickle", "reachable", "baseline", "pickle.loads",
         app("def load(blob):\n    return pickle.loads(blob)\n", "import pickle\n\n\n")),
    Case("base-eval", "reachable", "baseline", "builtins.eval",
         app("def calc(expr):\n    return eval(expr)\n", "")),
    Case("base-yaml", "reachable", "baseline", "yaml.load",
         app("def load(text):\n    return yaml.load(text)\n", "import yaml\n\n\n")),

    # --- caller-side guards ------------------------------------------------------
    Case("guard-caller-ok", "near_miss", "caller-guard", "builtins.open",
         app(VALIDATOR + "def read(name):\n    if not is_safe_name(name):\n        raise ValueError(name)\n"
             "    return open(name).read()\n", ""),
         pair="guard-caller-wrong-var", expect_guard="app.is_safe_name"),
    Case("guard-caller-wrong-var", "reachable", "caller-guard", "builtins.open",
         app(VALIDATOR + "def read(name, path):\n    if not is_safe_name(name):\n        raise ValueError(name)\n"
             "    return open(path).read()\n", ""),
         pair="guard-caller-ok", expect_guard=None, note="checks one variable, opens another"),
    Case("guard-caller-via-assignment", "near_miss", "caller-guard", "builtins.open",
         app(VALIDATOR + "BASE = '/srv/data'\n\n\ndef read(name):\n    if not is_safe_name(name):\n        raise ValueError(name)\n"
             "    path = BASE + '/' + name\n    return open(path).read()\n", ""),
         pair="guard-caller-partial", expect_guard="app.is_safe_name",
         note="guard reaches the sink through one assignment; the base directory is fixed"),
    Case("guard-caller-partial", "reachable", "caller-guard", "builtins.open",
         app(VALIDATOR + "def read(base, name):\n    if not is_safe_name(name):\n        raise ValueError(name)\n"
             "    path = base + '/' + name\n    return open(path).read()\n", ""),
         pair="guard-caller-via-assignment", expect_guard=None,
         note="only name is checked; the caller still picks base, so read('/etc', 'passwd') passes"),
    Case("guard-caller-reassigned", "reachable", "caller-guard", "builtins.open",
         app(VALIDATOR + "def read(name, other):\n    if not is_safe_name(name):\n        raise ValueError(name)\n"
             "    name = other\n    return open(name).read()\n", ""),
         pair="guard-caller-ok", expect_guard=None, note="checked value is overwritten before the sink"),
    Case("guard-caller-short-circuit", "reachable", "caller-guard", "builtins.open",
         app(VALIDATOR + "def read(name, strict):\n    if strict and not is_safe_name(name):\n        return None\n"
             "    return open(name).read()\n", ""),
         pair="guard-caller-ok", expect_guard=None, note="check is skipped when strict is false"),
    Case("guard-caller-not-dominating", "reachable", "caller-guard", "builtins.open",
         app(VALIDATOR + "def read(name, strict):\n    if strict:\n        if not is_safe_name(name):\n"
             "            raise ValueError(name)\n    return open(name).read()\n", ""),
         pair="guard-caller-ok", expect_guard=None),
    Case("guard-caller-after-sink", "reachable", "caller-guard", "builtins.open",
         app(VALIDATOR + "def read(name):\n    handle = open(name)\n    if not is_safe_name(name):\n"
             "        raise ValueError(name)\n    return handle.read()\n", ""),
         pair="guard-caller-ok", expect_guard=None),
    Case("guard-caller-loop-continue", "near_miss", "caller-guard", "builtins.open",
         app(VALIDATOR + "def read_all(names):\n    out = []\n    for name in names:\n"
             "        if not is_safe_name(name):\n            continue\n        out.append(open(name).read())\n"
             "    return out\n", ""),
         expect_guard="app.is_safe_name"),
    Case("guard-stdlib-predicate", "reachable", "caller-guard", "builtins.open",
         app("def read(path):\n    if not os.path.exists(path):\n        return None\n    return open(path).read()\n",
             "import os\n\n\n"),
         pair="guard-caller-ok", expect_guard=None, note="existence is not validation"),

    # --- callee-raises guards -------------------------------------------------------
    Case("guard-callee-ok", "near_miss", "callee-guard", "subprocess.run",
         app(RAISING_VALIDATOR + "def run(name):\n    require_safe_name(name)\n    return subprocess.run(['echo', name])\n"),
         pair="guard-callee-unrelated", expect_guard="app.require_safe_name"),
    Case("guard-callee-unrelated", "reachable", "callee-guard", "subprocess.run",
         app(RAISING_VALIDATOR + "def run(name, cmd):\n    require_safe_name(name)\n    return subprocess.run(cmd, shell=True)\n"),
         pair="guard-callee-ok", expect_guard=None, note="validator runs, but on a different value"),
    Case("guard-callee-producer", "reachable", "callee-guard", "subprocess.run",
         app("def build_command(name):\n    if not name:\n        raise ValueError(name)\n    return f'echo {name}'\n\n\n"
             "def run(name):\n    cmd = build_command(name)\n    return subprocess.run(cmd, shell=True)\n"),
         pair="guard-callee-ok", expect_guard=None, note="the raising call builds the command it would 'guard'"),

    # --- constant arguments --------------------------------------------------------
    Case("const-literal", "near_miss", "constant-args", "subprocess.run",
         app("def status():\n    return subprocess.run(['git', 'status'])\n"),
         pair="const-param", expect_constant=True),
    Case("const-param", "reachable", "constant-args", "subprocess.run",
         app("def run(args):\n    return subprocess.run(args)\n"),
         pair="const-literal", expect_constant=False),
    Case("const-default-param", "reachable", "constant-args", "subprocess.run",
         app("def run(cmd='ls'):\n    return subprocess.run(cmd, shell=True)\n"),
         pair="const-literal", expect_constant=False, note="a default is overridable by any caller"),
    Case("const-kwarg-user", "reachable", "constant-args", "subprocess.run",
         app("def run(code):\n    return subprocess.run('python', input=code, text=True)\n"),
         pair="const-literal", expect_constant=False, note="literal command, attacker-controlled stdin"),
    Case("const-env-call", "reachable", "constant-args", "builtins.eval",
         app("from os import getenv\n\n\ndef run():\n    return eval(getenv('USER_CODE'))\n", ""),
         expect_constant=False, note="constant input to a call whose result is external"),
    Case("const-module-constant", "near_miss", "constant-args", "subprocess.run",
         app("COMMAND = ['git', 'status']\n\n\ndef status():\n    return subprocess.run(COMMAND)\n"),
         pair="const-literal", expect_constant=True,
         note="truly constant, but through a module name; a known blind spot"),

    # --- code context -----------------------------------------------------------------
    Case("ctx-test-dir", "near_miss", "code-context", "subprocess.run",
         {"tests/test_tool.py": "import subprocess\n\n\ndef helper(cmd):\n    return subprocess.run(cmd, shell=True)\n"},
         pair="base-subprocess"),
    Case("ctx-test-file", "near_miss", "code-context", "subprocess.run",
         {"pkg/test_tool.py": "import subprocess\n\n\ndef helper(cmd):\n    return subprocess.run(cmd, shell=True)\n"},
         pair="base-subprocess"),
    Case("ctx-examples", "near_miss", "code-context", "subprocess.run",
         {"examples/demo.py": "import subprocess\n\n\ndef demo(cmd):\n    return subprocess.run(cmd, shell=True)\n"},
         pair="base-subprocess"),
    Case("ctx-nested-tools-is-product", "reachable", "code-context", "subprocess.run",
         {"pkg/tools/runner.py": "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"},
         pair="ctx-examples", note="a nested tools/ package is product code"),

    # --- sink signal --------------------------------------------------------------------
    Case("signal-json", "near_miss", "signal", "json.loads",
         app("def parse(text):\n    return json.loads(text)\n", "import json\n\n\n"),
         pair="base-pickle"),

    # --- aliases (resolved identity, not names) -------------------------------------------
    Case("alias-from-as", "reachable", "alias", "subprocess.run",
         app("def run(cmd):\n    return r(cmd, shell=True)\n", "from subprocess import run as r\n\n\n")),
    Case("alias-module-as", "reachable", "alias", "subprocess.run",
         app("def run(cmd):\n    return sp.run(cmd, shell=True)\n", "import subprocess as sp\n\n\n")),
    Case("alias-chain-2", "reachable", "alias", "subprocess.run",
         app("def run(cmd):\n    runner = subprocess.run\n    return runner(cmd, shell=True)\n")),
    Case("alias-from-import", "reachable", "alias", "os.system",
         app("def run(cmd):\n    return system(cmd)\n", "from os import system\n\n\n")),
    Case("alias-wrapper", "reachable", "alias", "subprocess.run",
         app("def _exec(command):\n    return subprocess.run(command, shell=True)\n\n\ndef run(cmd):\n    return _exec(cmd)\n"),
         note="sink lives in a one-line project wrapper"),

    # --- known gaps: measure honestly, do not expect detection ----------------------------
    Case("gap-getattr", "coverage_gap", "dynamic-dispatch", "os.system",
         app("def run(cmd):\n    return getattr(os, 'system')(cmd)\n", "import os\n\n\n")),
    Case("gap-dunder-import", "coverage_gap", "dynamic-dispatch", "os.system",
         app("def run(cmd):\n    return __import__('os').system(cmd)\n", "")),
    Case("gap-pathlib-write", "coverage_gap", "sink-family:pathlib", "pathlib.Path.write_text",
         app("def save(path, text):\n    Path(path).write_text(text)\n", "from pathlib import Path\n\n\n")),
    Case("gap-pathlib-open", "coverage_gap", "sink-family:pathlib", "pathlib.Path.open",
         app("def read(path):\n    with Path(path).open() as handle:\n        return handle.read()\n",
             "from pathlib import Path\n\n\n")),
    Case("gap-urlopen", "coverage_gap", "sink-family:network", "urllib.request.urlopen",
         app("def fetch(url):\n    return urllib.request.urlopen(url).read()\n", "import urllib.request\n\n\n")),
    Case("gap-requests", "coverage_gap", "sink-family:network", "requests.get",
         app("def fetch(url):\n    return requests.get(url).text\n", "import requests\n\n\n")),
    Case("gap-shutil-rmtree", "coverage_gap", "sink-family:file-ops", "shutil.rmtree",
         app("def wipe(path):\n    shutil.rmtree(path)\n", "import shutil\n\n\n")),
]
