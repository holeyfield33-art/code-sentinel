#!/usr/bin/env node
'use strict';
/* Node-side AST extraction for Sentinel-Zero's JS/TS resolver (Milestone 7).
 *
 * Deliberately bounded, the JS equivalent of Python's Milestone 1-2 bar, NOT
 * full parity with the Python resolver's five milestones:
 *   - "Caller" scopes are top-level function declarations and top-level
 *     `const name = function(){}` / `const name = () => {}` only. A class
 *     method, an object-literal method, an IIFE, or a callback passed
 *     inline is NOT its own scope here -- any calls inside one are simply
 *     not captured (same "don't guess, report nothing" discipline Python's
 *     earliest resolver draft used for lambdas).
 *   - require()/import bindings only (CommonJS destructuring and ESM named/
 *     default/namespace imports). Dynamic `import()` is not modeled --
 *     reported Unresolved like any other unrecognized callee shape.
 *   - Guard shape: a same-function, top-level `if (...) { throw ... }` or
 *     `if (...) { return ...; }`, same bar as Python's first guard check --
 *     no cross-function delegation walk on the JS side yet.
 *   - Loop bodies (for/while/do-while) are NOT given their own branch tag;
 *     calls inside them are recorded at the enclosing branch_path. This is
 *     a stated simplification, not a claim that loop iteration is modeled.
 *
 * Milestone 8 added external-dependency classification (which npm package
 * a call reaches), mirroring Python's Milestone 5 exactly: a resolved
 * call's top-level dotted component is "external" only if it is neither
 * one of this project's own top-level module segments nor a Node builtin
 * (require('module').builtinModules), AND the callee's root name is
 * provably bound (rootNameIsBound) rather than surviving only on
 * resolveDotted's unbound-name fallback -- the same two guards Python's
 * _root_name_is_bound exists to enforce, for the same reason (a local
 * variable's method call must never read as a dependency on a package of
 * the same name).
 *
 * Uses acorn (a real, standard JS parser) to get an actual AST -- never
 * regex/string matching, same rule the Python resolver enforces with
 * Python's own `ast` module. Invoked as a subprocess by js_resolver.py;
 * never imported into the running firewall/target code, no eval of target
 * source -- parsing only.
 *
 * Emits one JSON object on stdout: { modules, functions, errors, external_references }.
 */
const fs = require('fs');
const path = require('path');
const acorn = require('acorn');

const SKIP_DIR_NAMES = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage', '__pycache__']);

function findJsFiles(root) {
  const out = [];
  function walk(dir) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      return; // unreadable dir (permissions, broken symlink) -- skipped, not fatal to the whole scan
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (SKIP_DIR_NAMES.has(entry.name)) continue;
        walk(path.join(dir, entry.name));
      } else if (/\.(js|mjs|cjs)$/.test(entry.name)) {
        out.push(path.join(dir, entry.name));
      }
    }
  }
  walk(root);
  return out.sort();
}

function moduleQualname(filePath, root) {
  const rel = path.relative(root, filePath).replace(/\.(js|mjs|cjs)$/, '');
  let parts = rel.split(path.sep);
  if (parts[parts.length - 1] === 'index') parts = parts.slice(0, -1);
  return parts.length ? parts.join('.') : path.basename(filePath);
}

// A relative/absolute require()/import specifier ('./guard', '../x/y') must
// resolve to the SAME module-qualname format moduleQualname() gives the
// indexer, or cross-file delegation can never match up (found for real:
// a binding of './guard.requireRole' never matched the indexed function
// key 'guard.requireRole'). A bare specifier ('child_process', 'lodash')
// is an external package -- returned unchanged, not resolved to a file.
function resolveRequireSpecifier(specifier, currentFilePath, root) {
  if (!specifier.startsWith('.') && !specifier.startsWith('/')) {
    return specifier;
  }
  const currentDir = path.dirname(currentFilePath);
  const resolved = path.resolve(currentDir, specifier);
  const candidates = [resolved, `${resolved}.js`, `${resolved}.cjs`, `${resolved}.mjs`, path.join(resolved, 'index.js')];
  for (const candidate of candidates) {
    try {
      if (fs.statSync(candidate).isFile()) return moduleQualname(candidate, root);
    } catch (e) {
      // doesn't exist at this candidate path -- try the next one
    }
  }
  return null; // can't resolve to a real file -- binding left unmade, not guessed at
}

function collectBindings(programBody, currentFilePath, root) {
  const bindings = {};
  for (const stmt of programBody) {
    if (stmt.type === 'ImportDeclaration') {
      const source = resolveRequireSpecifier(stmt.source.value, currentFilePath, root);
      if (source === null) continue;
      for (const spec of stmt.specifiers) {
        if (spec.type === 'ImportDefaultSpecifier' || spec.type === 'ImportNamespaceSpecifier') {
          bindings[spec.local.name] = source;
        } else if (spec.type === 'ImportSpecifier') {
          bindings[spec.local.name] = `${source}.${spec.imported.name}`;
        }
      }
    } else if (stmt.type === 'VariableDeclaration') {
      for (const decl of stmt.declarations) {
        if (
          decl.init &&
          decl.init.type === 'CallExpression' &&
          decl.init.callee.type === 'Identifier' &&
          decl.init.callee.name === 'require' &&
          decl.init.arguments.length === 1 &&
          decl.init.arguments[0].type === 'Literal'
        ) {
          const source = resolveRequireSpecifier(decl.init.arguments[0].value, currentFilePath, root);
          if (source === null) continue;
          if (decl.id.type === 'Identifier') {
            bindings[decl.id.name] = source;
          } else if (decl.id.type === 'ObjectPattern') {
            for (const prop of decl.id.properties) {
              if (prop.type === 'Property' && prop.key.type === 'Identifier' && prop.value.type === 'Identifier') {
                bindings[prop.value.name] = `${source}.${prop.key.name}`;
              }
            }
          }
        }
      }
    }
  }
  return bindings;
}

function resolveDotted(node, bindings) {
  if (!node) return null;
  if (node.type === 'Identifier') {
    return Object.prototype.hasOwnProperty.call(bindings, node.name) ? bindings[node.name] : node.name;
  }
  if (node.type === 'MemberExpression' && !node.computed && node.property.type === 'Identifier') {
    const base = resolveDotted(node.object, bindings);
    return base ? `${base}.${node.property.name}` : null;
  }
  return null;
}

// Mirrors python_resolver.py's _root_name_is_bound exactly: a resolved
// dotted string alone isn't enough to trust as "this reaches an external
// package" -- resolveDotted falls back to an unbound bare name for a
// same-module reference, same reason Python's does. Only trust it when the
// expression's root Identifier is a real key in the binding map (a real
// require()/import), not a bare-fallback guess.
function rootNameIsBound(node, bindings) {
  while (node && node.type === 'MemberExpression') node = node.object;
  return !!node && node.type === 'Identifier' && Object.prototype.hasOwnProperty.call(bindings, node.name);
}

function isBuiltinTopLevel(topLevel, builtinModules) {
  const stripped = topLevel.startsWith('node:') ? topLevel.slice(5) : topLevel;
  return builtinModules.has(stripped) || builtinModules.has(topLevel);
}

function isGuardShaped(fnNode) {
  const body = fnNode.body.type === 'BlockStatement' ? fnNode.body.body : [];
  for (const stmt of body) {
    if (stmt.type === 'IfStatement') {
      for (const branch of [stmt.consequent, stmt.alternate]) {
        if (!branch) continue;
        const stmts = branch.type === 'BlockStatement' ? branch.body : [branch];
        for (const s of stmts) {
          if (s.type === 'ThrowStatement' || s.type === 'ReturnStatement') return true;
        }
      }
    }
  }
  return false;
}

// Full, scope-blind walk (nested closures included on purpose -- this is a
// structural existence check, not call-graph population, same reason
// Python's _dispatch_forwards_to uses plain ast.walk instead of the
// scope-respecting record_calls_in_expr). Looks for this.<attr>(...)
// anywhere under `node`.
function forwardsToThisAttr(node, attr) {
  if (!isNode(node)) return false;
  if (
    node.type === 'CallExpression' &&
    node.callee.type === 'MemberExpression' &&
    node.callee.object.type === 'ThisExpression' &&
    !node.callee.computed &&
    node.callee.property.type === 'Identifier' &&
    node.callee.property.name === attr
  ) {
    return true;
  }
  for (const key of Object.keys(node)) {
    if (key === 'type' || key === 'start' || key === 'end' || key === 'loc' || key === 'range') continue;
    const val = node[key];
    if (Array.isArray(val)) {
      if (val.some((item) => forwardsToThisAttr(item, attr))) return true;
    } else if (isNode(val) && forwardsToThisAttr(val, attr)) {
      return true;
    }
  }
  return false;
}

// Mirrors python_resolver.py's _init_wrapped_param_index exactly, `this`
// in place of `self`: if the constructor stores one of its own simple
// (non-destructured) parameters directly onto `this.<attr>`, returns
// [paramIndex, attr]. No attribute or parameter name is hardcoded -- same
// "generic shape of a wrapper holding what it wraps," not a Horos/ASGI-
// specific pattern.
function ctorWrappedParamIndex(ctorFnNode) {
  const paramNames = ctorFnNode.params.filter((p) => p.type === 'Identifier').map((p) => p.name);
  let found = null;
  function walk(node) {
    if (found || !isNode(node)) return;
    if (
      node.type === 'AssignmentExpression' &&
      node.operator === '=' &&
      node.left.type === 'MemberExpression' &&
      node.left.object.type === 'ThisExpression' &&
      !node.left.computed &&
      node.left.property.type === 'Identifier' &&
      node.right.type === 'Identifier' &&
      paramNames.includes(node.right.name)
    ) {
      found = [paramNames.indexOf(node.right.name), node.left.property.name];
      return;
    }
    for (const key of Object.keys(node)) {
      if (key === 'type' || key === 'start' || key === 'end' || key === 'loc' || key === 'range') continue;
      const val = node[key];
      if (Array.isArray(val)) val.forEach(walk);
      else if (isNode(val)) walk(val);
    }
  }
  walk(ctorFnNode.body);
  return found;
}

function isNode(x) {
  return x && typeof x === 'object' && typeof x.type === 'string';
}

// Collects CallExpression/NewExpression nodes within `node`, WITHOUT
// descending into a nested function literal's body -- that's a separate
// scope, not walked as part of the enclosing caller (mirrors Python's
// `continue` on nested FunctionDef in walk_stmts).
function findCallsInExpr(node, out) {
  if (!isNode(node)) return;
  if (node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression' || node.type === 'FunctionDeclaration') {
    return;
  }
  if (node.type === 'CallExpression' || node.type === 'NewExpression') {
    const isRequireCall =
      node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'require';
    if (!isRequireCall) {
      // require() is a binding form (collectBindings already consumed it),
      // the same way Python's `import` is its own AST node and never shows
      // up as a CallSite -- it must not either, here.
      out.push(node);
    }
  }
  for (const key of Object.keys(node)) {
    if (key === 'type' || key === 'start' || key === 'end' || key === 'loc' || key === 'range') continue;
    const val = node[key];
    if (Array.isArray(val)) {
      for (const item of val) findCallsInExpr(item, out);
    } else if (isNode(val)) {
      findCallsInExpr(val, out);
    }
  }
}

function parseFile(filePath) {
  let source;
  try {
    source = fs.readFileSync(filePath, 'utf8');
  } catch (e) {
    return { error: `could not read file: ${e.message}` };
  }
  try {
    const program = acorn.parse(source, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      locations: true,
      allowReturnOutsideFunction: true,
      allowImportExportEverywhere: true,
    });
    return { program, source };
  } catch (e) {
    return { error: `${e.name || 'ParseError'}: ${e.message}` };
  }
}

// Pass 1 (project-wide, like python_resolver.py's build_project_graph):
// index every top-level function, const-assigned function/arrow, and class
// (including wrapper-middleware detection) -- NO call-walking here. This
// has to finish for every file before pass 2 can resolve a same-module
// sibling call to its qualified form (see walkCalls below), the same
// reason Python builds graph.functions before resolving any calls.
function indexFile(program, filePath, modQ) {
  const functionsOut = {};
  const wrapperClassesOut = {};

  function indexFunction(qualname, fnNode) {
    functionsOut[qualname] = {
      qualified_name: qualname,
      is_guard_shaped: isGuardShaped(fnNode),
      file_path: filePath,
      lineno: fnNode.loc.start.line,
    };
  }

  // Milestone 9: wrapper-middleware detection, mirroring python_resolver.py's
  // _index_module_functions ClassDef branch exactly (this.<attr> in place of
  // self.<attr>, no __call__ convention assumed -- JS has none, so ANY
  // non-constructor method that forwards to the wrapped attribute counts,
  // framework-agnostic on purpose, same reason the Python version never
  // names Starlette/ASGI/Horos anywhere).
  //
  // Every class method is indexed into functionsOut (is_guard_shaped
  // included) the same way Python indexes every method -- but, matching
  // Python's own real, documented gap (see dogfood_scan.py Milestone 6's
  // commit message), method bodies are NOT walked for CallSite recording.
  // A wrapper's dispatch method is detected structurally without needing
  // its calls in the graph at all.
  function indexClass(classQualname, classNode) {
    let ctorNode = null;
    const otherMethods = [];
    for (const member of classNode.body.body) {
      if (member.type !== 'MethodDefinition' || member.key.type !== 'Identifier' || member.computed) continue;
      if (member.kind === 'constructor') {
        ctorNode = member.value;
        continue;
      }
      if (member.kind !== 'method') continue; // getters/setters/static out of scope for v0
      const methodQualname = `${classQualname}.${member.key.name}`;
      functionsOut[methodQualname] = {
        qualified_name: methodQualname,
        is_guard_shaped: isGuardShaped(member.value),
        file_path: filePath,
        lineno: member.loc.start.line,
      };
      otherMethods.push({ name: member.key.name, qualname: methodQualname, fnNode: member.value });
    }
    if (!ctorNode) return;
    const wrapped = ctorWrappedParamIndex(ctorNode);
    if (!wrapped) return;
    const [paramIndex, attr] = wrapped;
    const dispatch = otherMethods.find((m) => forwardsToThisAttr(m.fnNode.body, attr));
    if (!dispatch) return;
    wrapperClassesOut[classQualname] = {
      qualified_name: classQualname,
      wrapped_param_index: paramIndex,
      dispatch_method: dispatch.qualname,
      dispatch_is_guarded: isGuardShaped(dispatch.fnNode),
    };
  }

  for (const stmt of program.body) {
    if (stmt.type === 'FunctionDeclaration' && stmt.id) {
      indexFunction(`${modQ}.${stmt.id.name}`, stmt);
    } else if (stmt.type === 'VariableDeclaration') {
      for (const decl of stmt.declarations) {
        if (
          decl.id.type === 'Identifier' &&
          decl.init &&
          (decl.init.type === 'FunctionExpression' || decl.init.type === 'ArrowFunctionExpression')
        ) {
          indexFunction(`${modQ}.${decl.id.name}`, decl.init);
        }
      }
    } else if (stmt.type === 'ClassDeclaration' && stmt.id) {
      indexClass(`${modQ}.${stmt.id.name}`, stmt);
    }
  }

  return { functions: functionsOut, wrapper_classes: wrapperClassesOut };
}

// Pass 2 (project-wide functions already known): walk every top-level
// function/class-method-free body and module scope for CallSite recording,
// resolving each callee's dotted name and -- mirroring python_resolver.py's
// record_calls_in_expr exactly -- preferring the module-qualified candidate
// over the bare one when the bare form is actually a same-module sibling
// function, not a real module-qualified reference. Without this, a call to
// a sibling function defined in the SAME FILE resolved to the bare name
// ("helper") instead of "mod.helper", which graph.functions is always keyed
// by -- found while building wrapper-construction detection, since
// `new SomeWrapper(...)` in the wrapper's own defining file is the common
// case and must resolve to match graph.wrapper_classes' key.
//
// A class itself is never a key in projectFunctions (only its methods are,
// e.g. "mod.TokenWall.handle") -- so `new TokenWall(...)` in TokenWall's own
// file needs projectWrapperClasses checked too, or it falls back to the bare
// name and find_wrap_constructions' lookup into graph.wrapper_classes (keyed
// by the qualified class name) silently misses same-file construction sites.
// Caught by dogfooding test_js_wrapper_middleware.py's same-file case.
function walkCalls(
  program,
  filePath,
  modQ,
  bindings,
  source,
  projectFunctions,
  projectWrapperClasses,
  projectTopLevelNames,
  builtinModules
) {
  const calls = [];
  const externalReferences = [];

  function recordCallsFromNodes(nodeList, branchPath, callerName, orderCounter) {
    const sorted = nodeList.slice().sort((a, b) => a.start - b.start);
    for (const node of sorted) {
      const calleeNode = node.callee;
      const dotted = resolveDotted(calleeNode, bindings);
      let target;
      if (dotted) {
        const qualified = `${modQ}.${dotted}`;
        const qualifiedIsKnown =
          Object.prototype.hasOwnProperty.call(projectFunctions, qualified) ||
          Object.prototype.hasOwnProperty.call(projectWrapperClasses, qualified);
        const resolvedName = qualifiedIsKnown ? qualified : dotted;
        target = { kind: 'symbol', qualified_name: resolvedName };
        if (resolvedName.includes('.')) {
          const topLevel = resolvedName.split('.')[0];
          if (
            !projectTopLevelNames.has(topLevel) &&
            !isBuiltinTopLevel(topLevel, builtinModules) &&
            rootNameIsBound(calleeNode, bindings)
          ) {
            externalReferences.push({
              caller: callerName,
              package: topLevel,
              qualified_name: resolvedName,
              file_path: filePath,
              lineno: node.loc.start.line,
            });
          }
        }
      } else {
        target = {
          kind: 'unresolved',
          reason:
            `callee expression at line ${node.loc.start.line} did not resolve to a dotted name ` +
            '(dynamic dispatch, computed member access, or an import form this resolver doesn\'t model).',
        };
      }
      let argTexts = [];
      try {
        argTexts = node.arguments.map((a) => source.slice(a.start, a.end));
      } catch (e) {
        argTexts = [];
      }
      orderCounter.n += 1;
      calls.push({
        caller: callerName,
        target,
        lineno: node.loc.start.line,
        order: orderCounter.n,
        args: argTexts,
        branch_path: branchPath,
      });
    }
  }

  function walkStmts(stmts, branchPath, callerName, orderCounter) {
    for (const stmt of stmts) {
      if (stmt.type === 'FunctionDeclaration') continue; // separate scope, indexed on its own
      if (stmt.type === 'IfStatement') {
        const testCalls = [];
        findCallsInExpr(stmt.test, testCalls); // the test always runs
        recordCallsFromNodes(testCalls, branchPath, callerName, orderCounter);
        const tag = stmt.start;
        const consBody = stmt.consequent.type === 'BlockStatement' ? stmt.consequent.body : [stmt.consequent];
        walkStmts(consBody, branchPath.concat([[tag, 'body']]), callerName, orderCounter);
        if (stmt.alternate) {
          const altBody = stmt.alternate.type === 'BlockStatement' ? stmt.alternate.body : [stmt.alternate];
          walkStmts(altBody, branchPath.concat([[tag, 'orelse']]), callerName, orderCounter);
        }
        continue;
      }
      if (stmt.type === 'BlockStatement') {
        walkStmts(stmt.body, branchPath, callerName, orderCounter);
        continue;
      }
      if (stmt.type === 'TryStatement') {
        // Not given mutual-exclusivity tracking in JS v0 (stated limitation,
        // same as Python's Try handling at this stage) -- try/catch/finally
        // bodies are walked at the same branch_path as the try itself.
        walkStmts(stmt.block.body, branchPath, callerName, orderCounter);
        if (stmt.handler && stmt.handler.body) walkStmts(stmt.handler.body.body, branchPath, callerName, orderCounter);
        if (stmt.finalizer) walkStmts(stmt.finalizer.body, branchPath, callerName, orderCounter);
        continue;
      }
      // Generic statement (ExpressionStatement, VariableDeclaration, Return,
      // Throw, loop headers/bodies, etc.): collect every call anywhere
      // inside it at the current branch_path. findCallsInExpr already
      // refuses to descend into a nested function literal, so this cannot
      // double-count a const-assigned function's own body.
      const found = [];
      findCallsInExpr(stmt, found);
      recordCallsFromNodes(found, branchPath, callerName, orderCounter);
    }
  }

  // Index all top-level function/class-member qualnames in THIS file, so
  // walkStmts below can tell "this call's enclosing function is itself a
  // caller scope" from "it's some nested closure" -- indexFile (pass 1)
  // already built the project-wide version of this; this file-local index
  // is only used to find each function's own body to walk.
  const callerFunctions = [];
  for (const stmt of program.body) {
    if (stmt.type === 'FunctionDeclaration' && stmt.id) {
      callerFunctions.push([`${modQ}.${stmt.id.name}`, stmt]);
    } else if (stmt.type === 'VariableDeclaration') {
      for (const decl of stmt.declarations) {
        if (
          decl.id.type === 'Identifier' &&
          decl.init &&
          (decl.init.type === 'FunctionExpression' || decl.init.type === 'ArrowFunctionExpression')
        ) {
          callerFunctions.push([`${modQ}.${decl.id.name}`, decl.init]);
        }
      }
    }
  }
  for (const [qualname, fnNode] of callerFunctions) {
    if (fnNode.body.type === 'BlockStatement') {
      walkStmts(fnNode.body.body, [], qualname, { n: 0 });
    }
  }

  walkStmts(program.body, [], '', { n: 0 }); // module-scope calls, caller = ""

  return { calls, external_references: externalReferences };
}

function main() {
  const root = process.argv[2];
  if (!root) {
    process.stdout.write(JSON.stringify({ error: 'usage: extract_graph.js REPO_ROOT' }));
    process.exitCode = 2;
    return;
  }
  const files = findJsFiles(root);
  const projectTopLevelNames = new Set(files.map((f) => moduleQualname(f, root).split('.')[0]));
  const builtinModules = new Set(require('module').builtinModules);

  const modules = {};
  const functions = {};
  const wrapperClasses = {};
  const errors = [];
  const externalReferences = [];

  const parsed = []; // {filePath, modQ, program, source, bindings}
  for (const filePath of files) {
    const result = parseFile(filePath);
    if (result.error) {
      errors.push({ file_path: filePath, error: result.error });
      continue;
    }
    const modQ = moduleQualname(filePath, root);
    const bindings = collectBindings(result.program.body, filePath, root);
    parsed.push({ filePath, modQ, program: result.program, source: result.source, bindings });
  }

  // Pass 1: index every function/class across the WHOLE project before
  // resolving a single call -- see walkCalls's docstring for exactly why
  // (a same-module sibling call must resolve to its qualified form).
  for (const { filePath, modQ, program } of parsed) {
    const indexed = indexFile(program, filePath, modQ);
    Object.assign(functions, indexed.functions);
    Object.assign(wrapperClasses, indexed.wrapper_classes);
  }

  // Pass 2: now that `functions` is project-wide, walk every file for calls.
  for (const { filePath, modQ, program, source, bindings } of parsed) {
    const walked = walkCalls(
      program,
      filePath,
      modQ,
      bindings,
      source,
      functions,
      wrapperClasses,
      projectTopLevelNames,
      builtinModules
    );
    modules[modQ] = { file_path: filePath, calls: walked.calls };
    externalReferences.push(...walked.external_references);
  }

  process.stdout.write(
    JSON.stringify({ modules, functions, wrapper_classes: wrapperClasses, errors, external_references: externalReferences })
  );
}

main();
