import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";
import { STATUS_COLOR, DIFF_COLOR as DIFF_COLOR_HEX, toThreeHex } from "./colors.js";

// Converted once from colors.js's hex strings (the single source of truth
// shared with main.js's legend) into Three.js color ints -- never a
// second hardcoded copy of these colors. See colors.js's own docstring.
const DISPOSITION_COLOR = Object.fromEntries(
  Object.entries(STATUS_COLOR).map(([status, hex]) => [status, toThreeHex(hex)])
);
const NO_FINDING_COLOR = DISPOSITION_COLOR.none;
const UNRESOLVED_EDGE_COLOR = 0x5a2a2a;
const RESOLVED_EDGE_COLOR = 0x33415a;

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
    this._rebuildScene();
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
    this._rebuildScene();
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
      if (obj.userData?.isGraphContent) this.scene.remove(obj);
    }
    this.nodeMeshes = [];
    if (!this.graph || !this.layout) return;

    const filteringActive = this.filterCategories !== null || this.searchText !== "";

    const matched = new Set();
    for (const node of this.graph.nodes) {
      if (!filteringActive || this._passesOwnFilter(node)) matched.add(node.id);
    }

    // Path context: a matching node's direct callers (one hop), kept
    // visible-but-dim so an isolated node isn't shown floating with no
    // indication of how it's reached. Only computed when filtering --
    // with no filter active, everything is already visible.
    const contextOnly = new Set();
    if (filteringActive) {
      for (const edge of this.graph.edges) {
        if (edge.kind === "calls" && edge.target && matched.has(edge.target) && !matched.has(edge.source)) {
          contextOnly.add(edge.source);
        }
      }
    }
    const visible = filteringActive ? new Set([...matched, ...contextOnly]) : null; // null = everyone

    const nodeGroup = new THREE.Group();
    nodeGroup.userData.isGraphContent = true;

    for (const node of this.graph.nodes) {
      if (visible && !visible.has(node.id)) continue;
      const pos = this.layout.positionOf(node.id);
      if (!pos) continue;

      const isContext = contextOnly.has(node.id);
      const radius = node.kind === "module" ? 1.8 : 1.0;
      const geometry = new THREE.SphereGeometry(radius, 16, 16);
      const { color, emissiveIntensity } = isContext
        ? { color: NO_FINDING_COLOR, emissiveIntensity: 0.04 }
        : this._colorAndEmissiveFor(node);
      const material = new THREE.MeshStandardMaterial({
        color,
        emissive: color,
        emissiveIntensity,
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
    }

    const edgeGroup = new THREE.Group();
    edgeGroup.userData.isGraphContent = true;
    const edgePositions = { resolved: [], unresolved: [] };

    for (const edge of this.graph.edges) {
      if (edge.kind !== "calls") continue;
      if (visible && !visible.has(edge.source)) continue;
      const from = this.layout.positionOf(edge.source);
      if (!from) continue;
      const targetVisible = edge.target && (!visible || visible.has(edge.target));
      const to = targetVisible ? this.layout.positionOf(edge.target) : null;
      const bucket = edge.resolved && to ? edgePositions.resolved : edgePositions.unresolved;
      bucket.push(...from, ...(to ?? [from[0] + 0.6, from[1] + 0.6, from[2] + 0.6]));
    }

    for (const [key, color] of [
      ["resolved", RESOLVED_EDGE_COLOR],
      ["unresolved", UNRESOLVED_EDGE_COLOR],
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
  }

  _handleClick(ev) {
    const rect = this.renderer.domElement.getBoundingClientRect();
    this.pointer.x = ((ev.clientX - rect.left) / rect.width) * 2 - 1;
    this.pointer.y = -((ev.clientY - rect.top) / rect.height) * 2 + 1;
    this.raycaster.setFromCamera(this.pointer, this.camera);
    const hits = this.raycaster.intersectObjects(this.nodeMeshes, false);
    if (hits.length > 0 && this.onNodeClick) {
      this.onNodeClick(hits[0].object.userData.nodeData);
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
