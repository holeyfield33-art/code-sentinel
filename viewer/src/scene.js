import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";
import { projectGraph } from './studioModel.js';
import { STATUS_COLOR, DIFF_COLOR as DIFF_COLOR_HEX, toThreeHex } from "./colors.js";

// Converted once from colors.js's hex strings (the single source of truth
// shared with main.js's legend) into Three.js color ints -- never a
// second hardcoded copy of these colors. See colors.js's own docstring.
const DISPOSITION_COLOR = Object.fromEntries(
  Object.entries(STATUS_COLOR).map(([status, hex]) => [status, toThreeHex(hex)])
);
const NO_FINDING_COLOR = DISPOSITION_COLOR.none;
const UNRESOLVED_EDGE_COLOR = 0x924545;
const RESOLVED_EDGE_COLOR = 0x5588aa;

// Milestone 22 diff-mode colors, as Three.js ints -- same single source of
// truth (colors.js) as DISPOSITION_COLOR above and main.js's DIFF_LEGEND.
const DIFF_COLOR = Object.fromEntries(
  Object.entries(DIFF_COLOR_HEX).map(([cls, hex]) => [cls, toThreeHex(hex)])
);

function colorForDisposition(status) {
  return DISPOSITION_COLOR[status] ?? NO_FINDING_COLOR;
}

/**
 * Builds and owns the Three.js scene for one loaded graph. Deliberately
 * NOT a general-purpose "3D graph viewer" library abstraction -- this is
 * one file, built for exactly this viewer's one document shape
 * (graphLoader.js's validated output + layout.js's computed positions),
 * kept simple on purpose per "design what we need."
 *
 * Milestone 22 added two orthogonal view modes on top of the base
 * render:
 *   - a category+text FILTER (setFilter): non-matching nodes are
 *     dropped, but a matching node's direct CALLERS (one hop) are kept
 *     as dim "context" nodes so an isolated node doesn't float with no
 *     indication of how it's reached -- literally "isolate ... paths",
 *     not just "isolate ... nodes."
 *   - a DIFF overlay (setDiff): a node's color is driven by its
 *     classification against a second, previously-loaded baseline graph
 *     (new / changed / unchanged) instead of its own disposition.
 * Both are computed by _rebuildScene(), which is the one place node
 * visibility and color are decided -- render()/setFilter()/setDiff()/
 * clearDiff() only update state and call it, never duplicate its logic.
 */
export class GraphScene {
  constructor(container) {
    this.container = container;
    this.scene = new THREE.Scene();
    this.scene.background = new THREE.Color(0x0b0e14);

    this.camera = new THREE.PerspectiveCamera(
      60,
      container.clientWidth / container.clientHeight,
      0.1,
      5000
    );
    this.camera.position.set(0, 0, 160);

    this.renderer = new THREE.WebGLRenderer({ antialias: true });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    this.renderer.setSize(container.clientWidth, container.clientHeight);
    container.appendChild(this.renderer.domElement);

    this.controls = new OrbitControls(this.camera, this.renderer.domElement);
    this.controls.enableDamping = true;

    this.scene.add(new THREE.AmbientLight(0xffffff, 0.6));
    const dirLight = new THREE.DirectionalLight(0xffffff, 0.6);
    dirLight.position.set(1, 1, 1);
    this.scene.add(dirLight);

    this.raycaster = new THREE.Raycaster();
    this.pointer = new THREE.Vector2();
    this.nodeMeshes = []; // pickable sphere meshes currently in the scene, each carries userData.nodeId/nodeData
    this.onNodeClick = null; // set by main.js

    this.graph = null;
    this.layout = null;
    this.diffByNodeId = null; // Map<nodeId, {classification: "new"|"changed"|"unchanged", oldStatus, newStatus}> | null
    this.filterCategories = null; // Set<string> | null -- null means "no category filter, show everything"
    this.searchText = "";
    this.collapsed = new Set();
    this.investigation = false;
    this.hops = 1;
    this.selected = null;
    this.onViewChange = null;

    this.renderer.domElement.addEventListener("click", (ev) => this._handleClick(ev));
    window.addEventListener("resize", () => this._handleResize());

    this._animate();
  }

  /**
   * Loads a fresh graph+layout, clearing any filter or diff state from a
   * previously loaded graph -- a stale filter silently carried over to a
   * different document would be confusing, not convenient.
   * @param {{nodes: object[], edges: object[]}} graph
   * @param {import('./layout.js').ForceLayout3D} layout
   */
  render(graph, layout) {
    this.graph = graph;
    this.layout = layout;
    this.diffByNodeId = null;
    this.filterCategories = null;
    this.searchText = "";
    this.collapsed.clear();
    this.selected = null;
    this._rebuildScene();
    this.frame();
  }

  select(id) {
    this.selected = id;
    const parent = projectGraph(this.graph).model.parent.get(id);
    if (parent) this.collapsed.delete(parent);
    this._rebuildScene();
    if (this.investigation) this.frame();
    const node = this.graph.nodes.find(n => n.id === id);
    if (node) this.onNodeClick?.(node);
  }

  toggleModule(id) {
    if (this.collapsed.has(id)) this.collapsed.delete(id); else this.collapsed.add(id);
    this._rebuildScene();
  }

  setMode(investigation, hops = 1) {
    this.investigation = investigation; this.hops = hops;
    this._rebuildScene(); this.frame();
  }

  frame() {
    if (!this.nodeMeshes.length) return;
    const box = new THREE.Box3();
    for (const mesh of this.nodeMeshes) box.expandByPoint(mesh.position);
    const center = box.getCenter(new THREE.Vector3());
    const size = box.getSize(new THREE.Vector3());
    const usableWidth = Math.max(360, this.container.clientWidth - 720);
    const aspect = usableWidth / this.container.clientHeight;
    const distance = Math.max(35, size.y, size.x / aspect, size.z) / Math.tan(THREE.MathUtils.degToRad(this.camera.fov / 2));
    this.controls.target.copy(center);
    this.camera.position.copy(center).add(new THREE.Vector3(0, 0, distance * 1.3));
    this.camera.far = Math.max(5000, distance * 5); this.camera.updateProjectionMatrix();
    this.controls.update();
  }

  /** @param {Map<string, object>} diffByNodeId see class docstring */
  setDiff(diffByNodeId) {
    this.diffByNodeId = diffByNodeId;
    this._rebuildScene();
  }

  clearDiff() {
    this.diffByNodeId = null;
    this._rebuildScene();
  }

  /**
   * @param {Set<string>|null} categories -- null clears the category filter
   * @param {string} searchText -- case-insensitive substring match on node id
   */
  setFilter(categories, searchText) {
    this.filterCategories = categories;
    this.searchText = (searchText || "").toLowerCase();
    if (this.searchText) {
      const model = projectGraph(this.graph).model;
      for (const node of this.graph.nodes) if (node.id.toLowerCase().includes(this.searchText)) this.collapsed.delete(model.parent.get(node.id));
    }
    this._rebuildScene();
    this.frame();
  }

  /** The category a node currently belongs to -- diff classification if a
   * diff is active, otherwise its own disposition (or "none"). This is
   * what both the legend and setFilter's categories compare against. */
  categoryOf(node) {
    if (this.diffByNodeId) {
      return this.diffByNodeId.get(node.id)?.classification ?? "unchanged";
    }
    return node.worst_disposition ?? "none";
  }

  _passesOwnFilter(node) {
    if (this.filterCategories && !this.filterCategories.has(this.categoryOf(node))) return false;
    if (this.searchText && !node.id.toLowerCase().includes(this.searchText)) return false;
    return true;
  }

  _colorAndEmissiveFor(node) {
    if (this.diffByNodeId) {
      const cls = this.diffByNodeId.get(node.id)?.classification ?? "unchanged";
      if (cls === "new") return { color: DIFF_COLOR.new, emissiveIntensity: 0.5 };
      if (cls === "changed") return { color: DIFF_COLOR.changed, emissiveIntensity: 0.5 };
      // unchanged: keep the node's own disposition color, but recede --
      // this is what lets a reviewer still see "this was already
      // VERIFIED_TRUE" without it competing visually with what's new.
      return { color: colorForDisposition(node.worst_disposition), emissiveIntensity: 0.12 };
    }
    const color = colorForDisposition(node.worst_disposition);
    return { color, emissiveIntensity: node.worst_disposition ? 0.35 : 0.08 };
  }

  _rebuildScene() {
    for (const obj of [...this.scene.children]) {
      if (obj.userData?.isGraphContent) {
        obj.traverse(child => { child.geometry?.dispose(); child.material?.map?.dispose(); child.material?.dispose(); });
        this.scene.remove(obj);
      }
    }
    this.nodeMeshes = [];
    if (!this.graph || !this.layout) return;
    const projection = projectGraph(this.graph, this);
    this.projection = projection;

    const filteringActive = this.filterCategories !== null || this.searchText !== "";

    const matched = new Set();
    for (const node of projection.nodes) {
      if (!filteringActive || this._passesOwnFilter(node)) matched.add(node.id);
    }

    // Path context: a matching node's direct callers (one hop), kept
    // visible-but-dim so an isolated node isn't shown floating with no
    // indication of how it's reached. Only computed when filtering --
    // with no filter active, everything is already visible.
    const contextOnly = new Set();
    if (filteringActive) {
      for (const edge of projection.edges) {
        if (edge.kind === "calls" && edge.resolved && edge.target && matched.has(edge.target) && !matched.has(edge.source)) {
          contextOnly.add(edge.source);
        }
      }
    }
    const visible = filteringActive ? new Set([...matched, ...contextOnly]) : null; // null = everyone

    const nodeGroup = new THREE.Group();
    nodeGroup.userData.isGraphContent = true;
    const bounds = new THREE.Box3();
    for (const node of projection.nodes) if (!visible || visible.has(node.id)) bounds.expandByPoint(new THREE.Vector3(...this.layout.positionOf(node.id)));
    const span = bounds.isEmpty() ? 30 : bounds.getSize(new THREE.Vector3()).length();
    const unit = Math.max(1.2, span / 140);
    const labelIds = new Set(projection.nodes.filter(n => n.kind === 'module')
      .sort((a,b) => (projection.model.moduleDegree.get(b.id) - projection.model.moduleDegree.get(a.id)) || (a.id < b.id ? -1 : 1))
      .slice(0, 12).map(n => n.id));
    if (this.selected) labelIds.add(this.selected);

    for (const node of projection.nodes) {
      if (visible && !visible.has(node.id)) continue;
      const pos = this.layout.positionOf(node.id);
      if (!pos) continue;

      const isContext = contextOnly.has(node.id);
      const radius = node.kind === "module" ? unit * 1.8 : unit;
      const geometry = new THREE.SphereGeometry(radius, 16, 16);
      const { color, emissiveIntensity } = isContext
        ? { color: NO_FINDING_COLOR, emissiveIntensity: 0.04 }
        : this._colorAndEmissiveFor(node);
      const material = new THREE.MeshStandardMaterial({
        color,
        emissive: color,
        emissiveIntensity: node.id === this.selected ? 1 : emissiveIntensity,
        roughness: 0.5,
        transparent: isContext,
        opacity: isContext ? 0.35 : 1,
      });
      const mesh = new THREE.Mesh(geometry, material);
      mesh.position.set(...pos);
      mesh.userData.nodeId = node.id;
      mesh.userData.nodeData = node;
      nodeGroup.add(mesh);
      this.nodeMeshes.push(mesh);
      if (labelIds.has(node.id)) {
        const canvas = document.createElement('canvas'); canvas.width = 512; canvas.height = 64;
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = '#d7dce3'; ctx.font = '24px sans-serif';
        ctx.fillText(node.id.split('.').slice(-2).join('.').slice(-36), 4, 38);
        const texture = new THREE.CanvasTexture(canvas);
        const label = new THREE.Sprite(new THREE.SpriteMaterial({map:texture, transparent:true, depthTest:false}));
        label.position.set(pos[0], pos[1] + unit * 3, pos[2]); label.scale.set(unit * 20, unit * 2.5, 1);
        nodeGroup.add(label);
      }
    }

    const edgeGroup = new THREE.Group();
    edgeGroup.userData.isGraphContent = true;
    const edgePositions = { resolved: [], unresolved: [], contains: [], aggregate: [] };
    const rendered = new Set(this.nodeMeshes.map(m => m.userData.nodeId));
    this.renderedEdges = [];

    for (const edge of projection.edges) {
      if (!rendered.has(edge.source)) continue;
      const from = this.layout.positionOf(edge.source);
      if (!from) continue;
      if (projection.model.byId.has(edge.target) && !rendered.has(edge.target)) continue;
      const targetVisible = edge.target && rendered.has(edge.target);
      const to = targetVisible && (edge.resolved || edge.kind === 'contains') ? this.layout.positionOf(edge.target) : null;
      const key = !to ? 'unresolved' : edge.kind === 'contains' ? 'contains' : edge.displayOnly ? 'aggregate' : 'resolved';
      const bucket = edgePositions[key];
      bucket.push(...from, ...(to ?? [from[0] + 0.6, from[1] + 0.6, from[2] + 0.6]));
      this.renderedEdges.push(edge);
      if (edge.kind === 'calls' && edge.resolved && to) {
        const start = new THREE.Vector3(...from), end = new THREE.Vector3(...to);
        const direction = end.clone().sub(start);
        if (direction.length() > 0.01) {
          const arrow = new THREE.ArrowHelper(direction.clone().normalize(), start.clone().lerp(end, 0.7), Math.min(3, direction.length() * 0.2), 0x72b9e8, 1.4, 0.7);
          edgeGroup.add(arrow);
        }
      }
    }

    for (const [key, color] of [
      ["resolved", RESOLVED_EDGE_COLOR],
      ["unresolved", UNRESOLVED_EDGE_COLOR],
      ["contains", 0x3f7882],
      ["aggregate", 0xb29aff],
    ]) {
      const verts = edgePositions[key];
      if (verts.length === 0) continue;
      const geom = new THREE.BufferGeometry();
      geom.setAttribute("position", new THREE.Float32BufferAttribute(new Float32Array(verts), 3));
      const mat = new THREE.LineBasicMaterial({ color, transparent: true, opacity: key === "resolved" ? 0.35 : 0.5 });
      edgeGroup.add(new THREE.LineSegments(geom, mat));
    }

    this.scene.add(edgeGroup);
    this.scene.add(nodeGroup);
    this.onViewChange?.();
  }

  _handleClick(ev) {
    const rect = this.renderer.domElement.getBoundingClientRect();
    this.pointer.x = ((ev.clientX - rect.left) / rect.width) * 2 - 1;
    this.pointer.y = -((ev.clientY - rect.top) / rect.height) * 2 + 1;
    this.raycaster.setFromCamera(this.pointer, this.camera);
    const hits = this.raycaster.intersectObjects(this.nodeMeshes, false);
    if (hits.length > 0 && this.onNodeClick) {
      this.select(hits[0].object.userData.nodeId);
    }
  }

  _handleResize() {
    const { clientWidth, clientHeight } = this.container;
    this.camera.aspect = clientWidth / clientHeight;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(clientWidth, clientHeight);
  }

  _animate() {
    requestAnimationFrame(() => this._animate());
    this.controls.update();
    this.renderer.render(this.scene, this.camera);
  }
}
