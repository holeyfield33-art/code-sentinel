#!/usr/bin/env node
'use strict';
/* Node-side AST extraction for Sentinel-Zero's JS/TS resolver (Milestone 7).
 *
 * Deliberately bounded, the JS equivalent of Python's Milestone 1-2 bar, NOT
 * full parity with the Python resolver's five milestones:
 *   - "Caller" scopes are top-level function declarations, top-level
 *     `const name = function(){}` / `const name = () => {}`, AND (as of
 *     Milestone 12) every class's constructor and methods -- `this` is
 *     bound to the owning class's qualname for each method's own walk,
 *     mirroring Python's Milestone 11/12 `self`/`cls` binding exactly.
 *     An object-literal method, an IIFE, or a callback passed inline is
 *     still NOT its own scope -- any calls inside one are simply not
 *     captured (same "don't guess, report nothing" discipline Python's
 *     earliest resolver draft used for lambdas).
 *   - require()/import bindings only (CommonJS destructuring and ESM named/
 *     default/namespace imports). Dynamic `import()` is not modeled --
 *     reported Unresolved like any other unrecognized callee shape.
 *   - Guard shape: a same-function, top-level `if (...) { throw ... }` or
 *     `if (...) { return ...; }` (isGuardShaped); a stricter throw-only
 *     variant (isRaiseGuardShaped, Milestone 12) is what cross-function
 *     delegation actually checks for the DELEGATION case -- see
 *     callgraph.py's transitively_guard_shaped and graph.py's
 *     FunctionInfo.raises_on_guard for why `return` alone cannot protect
 *     a caller. Delegation itself is NOT implemented in this file at all
 *     -- it lives entirely in the language-agnostic callgraph.py, which
 *     walks whichever resolver's graph it's given; nothing JS-specific is
 *     needed here for that to work (confirmed by
 *     test_js_resolver.py's test_delegation_walk_from_callgraph_py_works_unmodified_on_js_graph).
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
 * Milestone 15 added bounded sink-argument taint classification, mirroring
 * python_resolver.py's _classify_arg_taint exactly (see that file and
 * graph.py's CallSite.arg_taint docstring for the full statement of what
 * this is and is not -- same-function evidence only, never interprocedural
 * taint tracking). Each call's `arg_taint` array classifies its positional
 * arguments, by real AST shape, as "literal" / "parameter" / "unknown".
 *
 * Emits one JSON object on stdout: { modules, functions, errors, external_references }.
 */
const fs = require('fs');
const path = require('path');
const acorn = require('acorn');
const tsEstree = require('@typescript-eslint/typescript-estree');

const SKIP_DIR_NAMES = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage', '__pycache__']);

// Milestone 10: TypeScript support, bounded to plain .ts only -- NOT .tsx.
// JSX inside a .tsx file is a real, separate parser mode and out of scope
// for this pass; a .tsx file is simply not collected (same "don't guess"
// bound as the original JS-only scope). .d.ts is also excluded: a type-only
// declaration file has no runtime code, so collecting it would only ever
// add TSInterfaceDeclaration/TSTypeAliasDeclaration noise our walkers
// already ignore -- never a real function, class or call.
function isCollectableFile(name) {
  if (name.endsWith('.d.ts')) return false;
  return /\.(js|mjs|cjs|ts)$/.test(name);
}

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
      } else if (isCollectableFile(entry.name)) {
        out.push(path.join(dir, entry.name));
      }
    }
  }
  walk(root);
  return out.sort();
}

function moduleQualname(filePath, root) {
  const rel = path.relative(root, filePath).replace(/\.(js|mjs|cjs|ts)$/, '');
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
  const candidates = [
    resolved,
    `${resolved}.ts`,
    `${resolved}.js`,
    `${resolved}.cjs`,
    `${resolved}.mjs`,
    path.join(resolved, 'index.ts'),
    path.join(resolved, 'index.js'),
  ];
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
  // Milestone 12: `this` resolves only when the caller bound it (a class
  // method's walk binds bindings.this to the owning class's qualname --
  // see walkCalls below). Outside that context there is no sensible bare
  // fallback the way a plain Identifier has one, so this correctly
  // returns null (-> Unresolved) rather than guessing.
  if (node.type === 'ThisExpression') {
    return Object.prototype.hasOwnProperty.call(bindings, 'this') ? bindings['this'] : null;
  }
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
  if (node && node.type === 'ThisExpression') {
    return Object.prototype.hasOwnProperty.call(bindings, 'this');
  }
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

// Milestone 12: stricter sibling of isGuardShaped, used only for the
// DELEGATION case -- another function calling fnNode and trusting its
// shape to protect THAT CALLER's own control flow (mirrors Python's
// _is_raise_guard_shaped; see graph.py's FunctionInfo.raises_on_guard for
// the full reasoning). Requires a `throw`, not a plain `return`: a
// `return` inside fnNode only ends fnNode's own execution, never the
// caller's -- the caller's next statement runs regardless unless it
// checks fnNode's return value, which this resolver does not model. A
// `throw` genuinely propagates into the caller (absent an enclosing
// try/catch, also not modeled). isGuardShaped (throw-OR-return) remains
// correct for the SAME-function dispatch shape (Milestone 9's wrapper
// detection) -- there, a `return` really does stop that same function's
// own next statement.
function isRaiseGuardShaped(fnNode) {
  const body = fnNode.body.type === 'BlockStatement' ? fnNode.body.body : [];
  for (const stmt of body) {
    if (stmt.type === 'IfStatement') {
      for (const branch of [stmt.consequent, stmt.alternate]) {
        if (!branch) continue;
        const stmts = branch.type === 'BlockStatement' ? branch.body : [branch];
        for (const s of stmts) {
          if (s.type === 'ThrowStatement') return true;
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
  // Milestone 12: TS parameter-property constructor sugar
  // (`constructor(private inner: Foo) {}`) auto-assigns `this.inner = inner`
  // with NO statement anywhere in the body for the walk below to find --
  // confirmed as a real, silent miss before this fix (Milestone 10's
  // test_parameter_property_constructor_sugar_not_detected_known_gap,
  // now superseded). TS's own rule for this syntax is that the parameter
  // name and the auto-assigned attribute name are always identical (no
  // renaming is possible), so this is detected straight from the
  // constructor's own param list -- checked first, in declaration order,
  // before the body-walk fallback below, since it can never be found any
  // other way. acorn-parsed (plain JS) constructors never produce this
  // node type, so this is a no-op for .js/.mjs/.cjs.
  for (let i = 0; i < ctorFnNode.params.length; i++) {
    const p = ctorFnNode.params[i];
    if (p.type === 'TSParameterProperty' && p.parameter && p.parameter.type === 'Identifier') {
      return [i, p.parameter.name];
    }
  }
  const paramNames = ctorFnNode.params.map((p) => (p.type === 'Identifier' ? p.name : null));
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

// Milestone 15 (JS/TS mirror of python_resolver.py's _param_names/
// _classify_arg_taint/_combine_taint -- same bound, same three labels, see
// graph.py's CallSite.arg_taint docstring for the full statement of what
// this is and is not). Collects the simple binding names a function's own
// parameter list introduces -- Identifier, ...rest, and a `= default`
// wrapper, plus TS parameter-property sugar's own parameter -- so
// classifyArgTaint can tell "this Identifier is one of THIS function's own
// parameters" from "it's some other name". Destructured params
// (ObjectPattern/ArrayPattern) are deliberately not modeled, same
// "don't guess" bound every other walker in this file already applies to
// shapes it doesn't resolve -- a destructured parameter's pieces simply
// classify as "unknown" below, never a wrong "parameter".
function collectParamName(p, names) {
  if (!p) return;
  if (p.type === 'Identifier') {
    names.add(p.name);
  } else if (p.type === 'RestElement') {
    collectParamName(p.argument, names);
  } else if (p.type === 'AssignmentPattern') {
    collectParamName(p.left, names);
  } else if (p.type === 'TSParameterProperty' && p.parameter) {
    collectParamName(p.parameter, names);
  }
}

function paramNamesFromFnNode(fnNode) {
  const names = new Set();
  for (const p of fnNode.params) collectParamName(p, names);
  return names;
}

// "least safe wins" aggregation, identical priority order to Python's
// _combine_taint: a composite expression (array/object/template literal/
// string concatenation) is only as safe as its least-safe piece.
function combineTaint(classifications) {
  if (classifications.length === 0) return 'literal';
  if (classifications.includes('parameter')) return 'parameter';
  if (classifications.includes('unknown')) return 'unknown';
  return 'literal';
}

// Classifies one sink-call argument expression by its real AST shape --
// never by re-rendering/re-parsing source text -- as "literal" (a constant,
// or built entirely from constants), "parameter" (traces to the enclosing
// function's own declared parameter, directly or through a simple member/
// concatenation/template-interpolation chain), or "unknown" (anything else:
// a call result, a global/module-level name, a destructured piece).
function classifyArgTaint(node, paramNames) {
  if (!isNode(node)) return 'unknown';
  if (node.type === 'Literal') return 'literal';
  if (node.type === 'TemplateLiteral') {
    // The literal text chunks (`quasis`) contribute nothing to taint --
    // only the `${...}` interpolations (`expressions`) can.
    return combineTaint(node.expressions.map((e) => classifyArgTaint(e, paramNames)));
  }
  if (node.type === 'ArrayExpression') {
    return combineTaint(
      node.elements.filter((e) => e !== null).map((e) => classifyArgTaint(e, paramNames))
    );
  }
  if (node.type === 'ObjectExpression') {
    const parts = [];
    for (const prop of node.properties) {
      if (prop.type === 'Property') {
        parts.push(classifyArgTaint(prop.value, paramNames));
        if (prop.computed) parts.push(classifyArgTaint(prop.key, paramNames));
      } else if (prop.type === 'SpreadElement') {
        parts.push(classifyArgTaint(prop.argument, paramNames));
      }
    }
    return combineTaint(parts);
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return combineTaint([classifyArgTaint(node.left, paramNames), classifyArgTaint(node.right, paramNames)]);
  }
  if (node.type === 'UnaryExpression') {
    return classifyArgTaint(node.argument, paramNames);
  }
  if (node.type === 'Identifier') {
    return paramNames.has(node.name) ? 'parameter' : 'unknown';
  }
  if (node.type === 'MemberExpression') {
    let base = node.object;
    while (base && base.type === 'MemberExpression') base = base.object;
    // ThisExpression as the base (this.foo.bar) is deliberately NOT treated
    // as "parameter" -- `this` is not one of the enclosing function's own
    // parameters, same reasoning that keeps a module-level global out of
    // "parameter" below.
    if (base && base.type === 'Identifier') return paramNames.has(base.name) ? 'parameter' : 'unknown';
    return 'unknown';
  }
  return 'unknown';
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

// typescript-estree gives every node a `range: [start, end]` array but,
// unlike acorn, no top-level `.start`/`.end` scalars -- and every walker
// below (findCallsInExpr's position sort, the arg-text `source.slice`
// extraction) reads `.start`/`.end` directly, inherited unchanged from the
// acorn-only era. Rather than touch every call site, backfill the two
// scalars from `range` once, right after a TS parse, so a TS-sourced AST
// is byte-for-byte interchangeable with an acorn one from here on.
function backfillRanges(node) {
  if (Array.isArray(node)) {
    for (const item of node) backfillRanges(item);
    return;
  }
  if (!node || typeof node !== 'object') return;
  if (typeof node.type === 'string' && Array.isArray(node.range) && node.start === undefined) {
    node.start = node.range[0];
    node.end = node.range[1];
  }
  for (const key of Object.keys(node)) {
    if (key === 'range' || key === 'loc' || key === 'parent') continue;
    const val = node[key];
    if (val && typeof val === 'object') backfillRanges(val);
  }
}

// Milestone 10: .ts files go through typescript-estree instead of acorn --
// acorn is a plain-JS parser and chokes on type annotations, interfaces,
// generics and decorators (confirmed by dogfooding real .ts fixtures
// before this milestone: every .ts-shaped construct in a .js file came
// back as a parse error). typescript-estree produces the SAME ESTree node
// shapes acorn does (FunctionDeclaration, ClassDeclaration, MethodDefinition
// with kind 'constructor'/'method', CallExpression, Identifier params even
// when type-annotated) -- confirmed by direct inspection -- so every walker
// below (findCallsInExpr, indexFile, walkCalls, forwardsToThisAttr,
// ctorWrappedParamIndex) needs zero changes to handle a TS-sourced AST.
// TS-only node types (TSInterfaceDeclaration, PropertyDefinition's type
// annotations, Decorator) simply fall through the existing type checks
// unrecognized, the same way an unrelated ESTree node always has.
function parseFile(filePath) {
  let source;
  try {
    source = fs.readFileSync(filePath, 'utf8');
  } catch (e) {
    return { error: `could not read file: ${e.message}` };
  }
  const isTs = filePath.endsWith('.ts');
  try {
    let program;
    if (isTs) {
      program = tsEstree.parse(source, { loc: true, range: true, jsx: false, errorOnUnknownASTType: false });
      backfillRanges(program);
    } else {
      program = acorn.parse(source, {
        ecmaVersion: 'latest',
        sourceType: 'module',
        locations: true,
        allowReturnOutsideFunction: true,
        allowImportExportEverywhere: true,
      });
    }
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
      raises_on_guard: isRaiseGuardShaped(fnNode),
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
  // included) the same way Python indexes every method, INCLUDING the
  // constructor (mirroring Python indexing __init__ too). Milestone 12
  // closed the gap the comment here used to describe: method bodies ARE
  // now walked for CallSite recording too (see walkCalls below, which
  // binds `this` to classQualname the same way Python's Milestone 11/12
  // bind `self`/`cls`) -- this function only INDEXES; walkCalls is a
  // separate pass. A wrapper's dispatch method is still detected
  // structurally here, without needing its calls in the graph at all.
  function indexClass(classQualname, classNode) {
    let ctorNode = null;
    const otherMethods = [];
    for (const member of classNode.body.body) {
      if (member.type !== 'MethodDefinition' || member.key.type !== 'Identifier' || member.computed) continue;
      if (member.kind === 'constructor') {
        ctorNode = member.value;
        const ctorQualname = `${classQualname}.constructor`;
        functionsOut[ctorQualname] = {
          qualified_name: ctorQualname,
          is_guard_shaped: isGuardShaped(member.value),
          raises_on_guard: isRaiseGuardShaped(member.value),
          file_path: filePath,
          lineno: member.loc.start.line,
        };
        continue;
      }
      if (member.kind !== 'method') continue; // getters/setters/static out of scope for v0
      const methodQualname = `${classQualname}.${member.key.name}`;
      functionsOut[methodQualname] = {
        qualified_name: methodQualname,
        is_guard_shaped: isGuardShaped(member.value),
        raises_on_guard: isRaiseGuardShaped(member.value),
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
  // Milestone 12: `bindings` is reassigned (not just read) below, for the
  // duration of each class method's walk, to add a `this` binding --
  // recordCallsFromNodes/resolveDotted/rootNameIsBound all close over
  // this same `bindings` variable (a function parameter, so reassignable
  // like any local), so reassigning it here is visible to them without
  // threading an extra argument through every call. fileBindings keeps
  // the original (require/import-only) bindings to restore between
  // methods and for the plain top-level-function/module-scope walks
  // below, which must NOT see a stale `this` from a previous class.
  const fileBindings = bindings;

  function recordCallsFromNodes(nodeList, branchPath, callerName, orderCounter, paramNames) {
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
      const argTaint = node.arguments.map((a) => classifyArgTaint(a, paramNames));
      orderCounter.n += 1;
      calls.push({
        caller: callerName,
        target,
        lineno: node.loc.start.line,
        order: orderCounter.n,
        args: argTexts,
        arg_taint: argTaint,
        branch_path: branchPath,
      });
    }
  }

  function walkStmts(stmts, branchPath, callerName, orderCounter, paramNames) {
    for (const stmt of stmts) {
      if (stmt.type === 'FunctionDeclaration') continue; // separate scope, indexed on its own
      if (stmt.type === 'IfStatement') {
        const testCalls = [];
        findCallsInExpr(stmt.test, testCalls); // the test always runs
        recordCallsFromNodes(testCalls, branchPath, callerName, orderCounter, paramNames);
        const tag = stmt.start;
        const consBody = stmt.consequent.type === 'BlockStatement' ? stmt.consequent.body : [stmt.consequent];
        walkStmts(consBody, branchPath.concat([[tag, 'body']]), callerName, orderCounter, paramNames);
        if (stmt.alternate) {
          const altBody = stmt.alternate.type === 'BlockStatement' ? stmt.alternate.body : [stmt.alternate];
          walkStmts(altBody, branchPath.concat([[tag, 'orelse']]), callerName, orderCounter, paramNames);
        }
        continue;
      }
      if (stmt.type === 'BlockStatement') {
        walkStmts(stmt.body, branchPath, callerName, orderCounter, paramNames);
        continue;
      }
      if (stmt.type === 'TryStatement') {
        // Not given mutual-exclusivity tracking in JS v0 (stated limitation,
        // same as Python's Try handling at this stage) -- try/catch/finally
        // bodies are walked at the same branch_path as the try itself.
        walkStmts(stmt.block.body, branchPath, callerName, orderCounter, paramNames);
        if (stmt.handler && stmt.handler.body) {
          walkStmts(stmt.handler.body.body, branchPath, callerName, orderCounter, paramNames);
        }
        if (stmt.finalizer) walkStmts(stmt.finalizer.body, branchPath, callerName, orderCounter, paramNames);
        continue;
      }
      // Generic statement (ExpressionStatement, VariableDeclaration, Return,
      // Throw, loop headers/bodies, etc.): collect every call anywhere
      // inside it at the current branch_path. findCallsInExpr already
      // refuses to descend into a nested function literal, so this cannot
      // double-count a const-assigned function's own body.
      const found = [];
      findCallsInExpr(stmt, found);
      recordCallsFromNodes(found, branchPath, callerName, orderCounter, paramNames);
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
      walkStmts(fnNode.body.body, [], qualname, { n: 0 }, paramNamesFromFnNode(fnNode));
    }
  }

  // Milestone 12: every class's constructor and methods are walked for
  // CallSite recording too -- mirrors Python's Milestone 11/12 fix
  // exactly, closing the same class of gap (a sink call inside ANY
  // method was entirely invisible, not even Unresolved). `this` is bound
  // to the owning class's qualname for the duration of each one method's
  // walk, so `this.foo(...)` resolves through the same ThisExpression
  // handling just added to resolveDotted/rootNameIsBound -- no new
  // resolution mechanism beyond that. `bindings` is reset to
  // `fileBindings` (no `this`) before and after, so a method in one
  // class can never leak its `this` binding into a sibling class or back
  // into the plain top-level/module-scope walks above and below.
  for (const stmt of program.body) {
    if (stmt.type !== 'ClassDeclaration' || !stmt.id) continue;
    const classQualname = `${modQ}.${stmt.id.name}`;
    for (const member of stmt.body.body) {
      if (member.type !== 'MethodDefinition' || member.key.type !== 'Identifier' || member.computed) continue;
      if (member.kind !== 'constructor' && member.kind !== 'method') continue; // getters/setters/static out of scope for v0
      const methodName = member.kind === 'constructor' ? 'constructor' : member.key.name;
      const methodQualname = `${classQualname}.${methodName}`;
      if (member.value.body.type !== 'BlockStatement') continue;
      bindings = Object.assign({}, fileBindings, { this: classQualname });
      walkStmts(member.value.body.body, [], methodQualname, { n: 0 }, paramNamesFromFnNode(member.value));
      bindings = fileBindings;
    }
  }

  walkStmts(program.body, [], '', { n: 0 }, new Set()); // module-scope calls, caller = "", no parameters

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
