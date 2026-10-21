#!/usr/bin/env node
'use strict';
/* Milestone 18: JS/TS mirror of _sink_reachability_harness.py (Python's
 * Milestone 6/16 dynamic reachability probe). Same safety model, same
 * three outcomes ("sink_reached" / "not_reached" / "call_failed"), same
 * one-JSON-line-on-stdout contract -- see the Python harness's docstring
 * for the full philosophy; this file only covers what differs on the
 * Node side.
 *
 * Invoked ONLY as a subprocess, hard timeout enforced by the Python-side
 * driver (js_sink_reachability_probe.py) -- never imported into the
 * running scan process.
 *
 * What's safe to monkeypatch BEFORE require()'ing the target, confirmed
 * empirically before this file was written (see the commit message for
 * the exact test commands):
 *   - child_process's exec/execSync/execFile/execFileSync/spawn/
 *     spawnSync/fork: safe. Node's own module loader never calls these.
 *   - global eval and global Function: safe. Unlike Python (where the
 *     import machinery runs module bytecode via the builtin exec()),
 *     Node's CommonJS loader compiles and runs module code through
 *     internal V8 bindings, never through the redefinable global eval or
 *     Function constructor.
 *   - vm.Script, vm.compileFunction, vm.runInThisContext/runInNewContext/
 *     runInContext: safe, for the same reason -- confirmed directly that
 *     patching vm.Script does not break require().
 *   - JSON.parse: safe. Node's package.json resolution during require()
 *     does not route through the public, redefinable JSON.parse.
 *   - fs.readFile (the async callback form), fs.writeFile, fs.writeFileSync:
 *     safe.
 *
 * What is NOT safe, and is therefore never patched here:
 *   - fs.readFileSync. Node's CommonJS loader reads the target module's
 *     own source text via the real, public fs.readFileSync -- patching it
 *     breaks EVERY require(), not just a target that itself calls
 *     fs.readFileSync (confirmed directly). There is no safe "patch after
 *     require, before the call" workaround either, for the same reason
 *     Python's eval/exec don't get one: a probed function's own lazy
 *     require() of a THIRD file would trip a patched fs.readFileSync
 *     falsely, misattributing a false sink-reached to an unrelated
 *     import. A finding whose OWN sink is fs.readFileSync is therefore
 *     never probed at all (see js_sink_reachability_probe.py's caller),
 *     mirroring Python's builtins.eval/builtins.exec exclusion exactly.
 *
 * Eligibility (arity) is decided HERE, at runtime, via the real exported
 * function's own `.length` -- not via static source parsing on the
 * Python side the way Python's probe does it. This is deliberate, not a
 * shortcut: JS does not raise on a missing argument the way Python
 * raises TypeError for a missing required parameter -- calling a
 * multi-parameter JS function with zero arguments silently binds the
 * missing ones to `undefined` and runs anyway, which is NOT the same
 * "genuinely zero-argument, nothing synthesized" call this probe's
 * safety model promises. So `fn.length !== 0` is refused here, reported
 * as call_failed, never attempted -- the one thing Python's resolver
 * decides from source text, this harness decides from the real,
 * already-required function object, which is at least as accurate.
 *
 * Only a function that is genuinely reachable from the module's own
 * exports is ever probed -- a top-level function this resolver's static
 * analysis found is NOT necessarily exported (CommonJS requires an
 * explicit module.exports/exports.x assignment; ESM `export` syntax is
 * not even require()-able by plain Node without a loader). Both failure
 * modes report cleanly as call_failed, never guessed around.
 */
const path = require('path');

class SinkReached extends Error {
  constructor(symbol, argsRepr) {
    super(symbol);
    this.symbol = symbol;
    this.argsRepr = argsRepr;
  }
}

function recorder(symbol) {
  return function (...args) {
    let repr;
    try {
      repr = JSON.stringify(args).slice(0, 200);
    } catch (e) {
      repr = '<unserializable>';
    }
    throw new SinkReached(symbol, repr);
  };
}

function patchSinks() {
  const cp = require('child_process');
  cp.exec = recorder('child_process.exec');
  cp.execSync = recorder('child_process.execSync');
  cp.execFile = recorder('child_process.execFile');
  cp.execFileSync = recorder('child_process.execFileSync');
  cp.spawn = recorder('child_process.spawn');
  cp.spawnSync = recorder('child_process.spawnSync');
  cp.fork = recorder('child_process.fork');

  global.eval = recorder('eval');
  global.Function = recorder('Function');

  const fs = require('fs');
  // fs.readFileSync is deliberately NOT patched here -- see module
  // docstring. fs.readFile (async) is safe and is patched.
  fs.readFile = recorder('fs.readFile');
  fs.writeFile = recorder('fs.writeFile');
  fs.writeFileSync = recorder('fs.writeFileSync');

  const origJsonParse = JSON.parse;
  JSON.parse = recorder('JSON.parse');

  const vm = require('vm');
  vm.runInThisContext = recorder('vm.runInThisContext');
  vm.runInNewContext = recorder('vm.runInNewContext');
  vm.runInContext = recorder('vm.runInContext');
  vm.Script = recorder('vm.Script');
}

function main() {
  const filePath = process.argv[2];
  const functionName = process.argv[3];
  if (!filePath || !functionName) {
    process.stdout.write(JSON.stringify({
      status: 'call_failed',
      detail: 'usage: _sink_reachability_harness.js FILE_PATH FUNCTION_NAME',
    }));
    return;
  }

  patchSinks();

  let mod;
  try {
    mod = require(path.resolve(filePath));
  } catch (e) {
    process.stdout.write(JSON.stringify({
      status: 'call_failed',
      detail: `import failed: ${e.name || 'Error'}: ${e.message}`,
    }));
    return;
  }

  const fn = mod ? mod[functionName] : undefined;
  if (typeof fn !== 'function') {
    process.stdout.write(JSON.stringify({
      status: 'call_failed',
      detail: `${JSON.stringify(functionName)} not found or not a function on this module's exports ` +
        '(it may exist in source but not be exported -- CommonJS requires an explicit ' +
        'module.exports/exports.x assignment, and ESM export syntax is not require()-able directly).',
    }));
    return;
  }
  if (fn.length !== 0) {
    process.stdout.write(JSON.stringify({
      status: 'call_failed',
      detail: `${functionName} expects ${fn.length} argument(s) -- this probe only calls genuinely ` +
        'zero-argument functions (see module docstring: JS silently fills missing arguments with ' +
        'undefined rather than raising, which this probe treats as an unsafe, non-benign call shape).',
    }));
    return;
  }

  try {
    fn();
  } catch (e) {
    if (e instanceof SinkReached) {
      process.stdout.write(JSON.stringify({
        status: 'sink_reached',
        symbol: e.symbol,
        args: e.argsRepr,
      }));
      return;
    }
    process.stdout.write(JSON.stringify({
      status: 'call_failed',
      detail: `call raised: ${e.name || 'Error'}: ${e.message}`,
    }));
    return;
  }

  process.stdout.write(JSON.stringify({
    status: 'not_reached',
    detail: 'function returned without reaching a patched sink',
  }));
}

main();
