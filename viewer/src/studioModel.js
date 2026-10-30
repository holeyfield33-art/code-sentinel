// Display projections retain original objects and source edge indices. No inferred calls.
export const MAX_RENDER_NODES = 2500;
export const compareIds = (a, b) => a < b ? -1 : a > b ? 1 : 0;
export function architecture(graph) {
  const byId = new Map(graph.nodes.map(n => [n.id, n]));
  const parent = new Map();
  for (const e of graph.edges) if (e.kind === 'contains') parent.set(e.target, e.source);
  const paths = graph.nodes.filter(n => n.kind === 'module' && n.file_path).map(n => n.file_path.replaceAll('\\', '/'));
  const absolute = paths.filter(p => p.startsWith('/') || /^[A-Za-z]:\//.test(p));
  const prefix = absolute.length ? absolute[0].split('/').slice(0, -1) : [];
  for (const path of absolute) while (prefix.length && !path.startsWith(prefix.join('/') + '/')) prefix.pop();
  const relativePath = node => {
    const path = node.file_path?.replaceAll('\\', '/') ?? '(source unavailable)';
    return prefix.length && path.startsWith(prefix.join('/') + '/') ? path.slice(prefix.join('/').length + 1) : path;
  };
  const groups = new Map();
  for (const node of graph.nodes.filter(n => n.kind === 'module')) {
    const p = relativePath(node); const dir = p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '.';
    if (!groups.has(dir)) groups.set(dir, []);
    groups.get(dir).push(node.id);
  }
  const degree = new Map(graph.nodes.map(n => [n.id, 0]));
  const moduleDegree = new Map(graph.nodes.filter(n => n.kind === 'module').map(n => [n.id, 0]));
  graph.edges.forEach(e => {
    if (e.kind === 'calls' && e.resolved) {
      degree.set(e.source, (degree.get(e.source) ?? 0) + 1);
      if (byId.has(e.target)) degree.set(e.target, (degree.get(e.target) ?? 0) + 1);
      const modules = new Set([parent.get(e.source) ?? e.source, parent.get(e.target) ?? e.target]);
      for (const id of modules) if (moduleDegree.has(id)) moduleDegree.set(id, moduleDegree.get(id) + 1);
    }
  });
  return { byId, parent, groups, degree, moduleDegree, relativePath };
}

export function neighborhood(graph, selected, hops = 1) {
  const ids = new Set(selected ? [selected] : []);
  for (let i = 0; i < Math.min(2, Math.max(1, hops)); i++) {
    const before = new Set(ids);
    for (const e of graph.edges) if (e.kind === 'calls' && e.resolved && e.target != null) {
      if (before.has(e.source)) ids.add(e.target);
      if (before.has(e.target)) ids.add(e.source);
    }
  }
  return ids;
}

export function projectGraph(graph, { collapsed = new Set(), selected = null, investigation = false, hops = 1 } = {}) {
  const model = architecture(graph);
  const wanted = investigation && selected ? neighborhood(graph, selected, hops) : null;
  const representative = id => !investigation && collapsed.has(model.parent.get(id)) ? model.parent.get(id) : id;
  const nodes = graph.nodes.filter(n => (!wanted || wanted.has(n.id)) && representative(n.id) === n.id);
  const visible = new Set(nodes.map(n => n.id));
  const edges = []; const aggregates = new Map();
  graph.edges.forEach((edge, index) => {
    if (investigation && edge.kind !== 'calls') return;
    const source = representative(edge.source), target = representative(edge.target);
    if (!visible.has(source)) return;
    if (edge.kind === 'contains' && ((model.byId.has(target) && !visible.has(target)) || source === target)) return;
    if (model.byId.has(target) && !visible.has(target)) return;
    const changed = source !== edge.source || target !== edge.target;
    if (changed && edge.kind === 'calls' && source !== target) {
      const key = JSON.stringify([source, target, edge.resolved]);
      if (!aggregates.has(key)) aggregates.set(key, { source, target, kind: 'aggregate', resolved: edge.resolved, originalIndices: [], displayOnly: true });
      aggregates.get(key).originalIndices.push(index);
    } else if (!changed) edges.push({ ...edge, originalIndex: index, displayOnly: false });
  });
  return { nodes, edges: [...edges, ...aggregates.values()], model };
}
