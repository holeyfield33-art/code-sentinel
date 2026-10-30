import { architecture, compareIds } from './studioModel.js';

// Compatibility name retained. Deterministic clustered placement, O(V log V + E).
export class ForceLayout3D {
  constructor(nodes, edges) {
    const {groups, parent, degree} = architecture({nodes, edges});
    this.positions = new Map();
    const dirs = [...groups.keys()].sort(compareIds);
    const width = Math.ceil(Math.sqrt(dirs.length || 1));
    dirs.forEach((dir, groupIndex) => {
      const base = [(groupIndex % width) * 180, Math.floor(groupIndex / width) * 180, 0];
      groups.get(dir).sort(compareIds).forEach((id, i) => {
        const a = i * 2.399963229728653, r = 18 * Math.sqrt(i);
        this.positions.set(id, [base[0] + Math.cos(a)*r, base[1] + Math.sin(a)*r, 0]);
      });
    });
    const children = new Map();
    for (const n of nodes.filter(n => n.kind !== 'module')) {
      const p = parent.get(n.id) ?? '(unassigned)';
      if (!children.has(p)) children.set(p, []);
      children.get(p).push(n);
    }
    for (const [p, items] of [...children].sort(([a], [b]) => compareIds(a,b))) {
      const base = this.positions.get(p) ?? [-180, 0, 0];
      items.sort((a,b) => (degree.get(b.id) - degree.get(a.id)) || compareIds(a.id,b.id));
      items.forEach((n, i) => {
        const a = i * 2.399963229728653, r = 10 + 3 * Math.sqrt(i);
        this.positions.set(n.id, [base[0] + Math.cos(a)*r, base[1] + Math.sin(a)*r, 10 + (i % 5)*3]);
      });
    }
  }
  settle() {}
  positionOf(id) { return this.positions.get(id) ?? null; }
}
