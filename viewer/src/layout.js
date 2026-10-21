/**
 * A minimal, self-contained 3D force-directed layout. No graph-layout
 * dependency is added for this (no d3-force-3d, no three-forcegraph) --
 * this project's own graphs top out at a few thousand nodes/edges (a
 * self-scan of sentinel-zero itself is ~230 nodes / ~1500 edges), which a
 * plain O(n^2) repulsion pass handles in well under a frame budget once
 * the simulation has settled, and keeping this dependency-free matches
 * "design what we need, without adding onto existing projects" -- this
 * is a few dozen lines of real physics, not a library worth pulling in.
 *
 * Model: nodes repel each other (inverse-square, capped), edges pull
 * their two endpoints together (spring, Hooke's law), everything has
 * velocity damping, and the whole thing is integrated for a fixed number
 * of steps up front (not continuously -- a static graph doesn't need a
 * live physics loop, it needs to settle once and then just render).
 */

export class ForceLayout3D {
  /**
   * @param {{id: string}[]} nodes
   * @param {{source: string, target: string}[]} edges
   */
  constructor(nodes, edges) {
    this.nodeIds = nodes.map((n) => n.id);
    this.index = new Map(this.nodeIds.map((id, i) => [id, i]));
    const n = this.nodeIds.length;

    // Seed on a sphere, not a flat plane or a single point -- avoids the
    // "everything starts coplanar" degenerate case which the repulsion
    // force alone cannot reliably break out of in 3D.
    this.positions = new Float64Array(n * 3);
    for (let i = 0; i < n; i++) {
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      const r = 40 + Math.random() * 10;
      this.positions[i * 3 + 0] = r * Math.sin(phi) * Math.cos(theta);
      this.positions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      this.positions[i * 3 + 2] = r * Math.cos(phi);
    }
    this.velocities = new Float64Array(n * 3);

    // Only keep edges whose both endpoints are actual nodes in this
    // document -- an edge whose target is null (an unresolved call) or
    // whose target isn't a node we rendered (a stdlib sink symbol, e.g.
    // "os.system", which graph_export.py records as an edge target but
    // never as its own node) contributes nothing to the spring layout;
    // it's still drawn (see scene.js) as a short "stub" from its source,
    // just not treated as a layout constraint between two positions.
    this.springEdges = [];
    for (const e of edges) {
      const a = this.index.get(e.source);
      const b = this.index.get(e.target);
      if (a !== undefined && b !== undefined && a !== b) {
        this.springEdges.push([a, b]);
      }
    }
  }

  /** @param {number} steps */
  settle(steps = 220) {
    const n = this.nodeIds.length;
    if (n === 0) return;
    const repulsionStrength = 180;
    const springStrength = 0.06;
    const restLength = 14;
    const damping = 0.82;
    const maxForce = 12;

    for (let step = 0; step < steps; step++) {
      const forces = new Float64Array(n * 3);

      // Repulsion: O(n^2). Fine at this project's real graph sizes; if a
      // future scan produces tens of thousands of nodes, a Barnes-Hut
      // octree would be the honest next step rather than quietly letting
      // this degrade -- not needed yet, not pretended to be needed yet.
      for (let i = 0; i < n; i++) {
        for (let j = i + 1; j < n; j++) {
          const dx = this.positions[i * 3] - this.positions[j * 3];
          const dy = this.positions[i * 3 + 1] - this.positions[j * 3 + 1];
          const dz = this.positions[i * 3 + 2] - this.positions[j * 3 + 2];
          const distSq = Math.max(dx * dx + dy * dy + dz * dz, 0.5);
          const dist = Math.sqrt(distSq);
          const f = Math.min(repulsionStrength / distSq, maxForce);
          const fx = (dx / dist) * f;
          const fy = (dy / dist) * f;
          const fz = (dz / dist) * f;
          forces[i * 3] += fx;
          forces[i * 3 + 1] += fy;
          forces[i * 3 + 2] += fz;
          forces[j * 3] -= fx;
          forces[j * 3 + 1] -= fy;
          forces[j * 3 + 2] -= fz;
        }
      }

      // Springs: pull connected nodes toward restLength apart.
      for (const [a, b] of this.springEdges) {
        const dx = this.positions[b * 3] - this.positions[a * 3];
        const dy = this.positions[b * 3 + 1] - this.positions[a * 3 + 1];
        const dz = this.positions[b * 3 + 2] - this.positions[a * 3 + 2];
        const dist = Math.max(Math.sqrt(dx * dx + dy * dy + dz * dz), 0.01);
        const stretch = dist - restLength;
        const f = springStrength * stretch;
        const fx = (dx / dist) * f;
        const fy = (dy / dist) * f;
        const fz = (dz / dist) * f;
        forces[a * 3] += fx;
        forces[a * 3 + 1] += fy;
        forces[a * 3 + 2] += fz;
        forces[b * 3] -= fx;
        forces[b * 3 + 1] -= fy;
        forces[b * 3 + 2] -= fz;
      }

      // Mild pull toward the origin so disconnected components don't
      // drift off to infinity under pure repulsion.
      for (let i = 0; i < n; i++) {
        forces[i * 3] -= this.positions[i * 3] * 0.002;
        forces[i * 3 + 1] -= this.positions[i * 3 + 1] * 0.002;
        forces[i * 3 + 2] -= this.positions[i * 3 + 2] * 0.002;
      }

      for (let i = 0; i < n * 3; i++) {
        this.velocities[i] = (this.velocities[i] + forces[i]) * damping;
        this.positions[i] += this.velocities[i];
      }
    }
  }

  /** @returns {[number, number, number]} */
  positionOf(nodeId) {
    const i = this.index.get(nodeId);
    if (i === undefined) return null;
    return [this.positions[i * 3], this.positions[i * 3 + 1], this.positions[i * 3 + 2]];
  }
}
