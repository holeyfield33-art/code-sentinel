import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";

const DISPOSITION_COLOR = {
  VERIFIED_TRUE: 0xff5c5c,
  TOOL_FAILURE: 0xff5c5c,
  UNRESOLVED_INCONCLUSIVE: 0xf5c84c,
  VERIFIED_FALSE: 0x5ad1a0,
};
const NO_FINDING_COLOR = 0x3c4a63;
const UNRESOLVED_EDGE_COLOR = 0x5a2a2a;
const RESOLVED_EDGE_COLOR = 0x33415a;

function colorForDisposition(status) {
  return DISPOSITION_COLOR[status] ?? NO_FINDING_COLOR;
}

/**
 * Builds and owns the Three.js scene for one loaded graph. Deliberately
 * NOT a general-purpose "3D graph viewer" library abstraction -- this is
 * one file, built for exactly this viewer's one document shape
 * (graphLoader.js's validated output + layout.js's computed positions),
 * kept simple on purpose per "design what we need."
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
    this.nodeMeshes = []; // parallel to pickable sphere meshes, each carries userData.nodeId
    this.onNodeClick = null; // set by main.js

    this.renderer.domElement.addEventListener("click", (ev) => this._handleClick(ev));
    window.addEventListener("resize", () => this._handleResize());

    this._animate();
  }

  /**
   * Clears any previously rendered graph and builds a fresh one.
   * @param {{nodes: object[], edges: object[]}} graph
   * @param {import('./layout.js').ForceLayout3D} layout
   */
  render(graph, layout) {
    for (const obj of [...this.scene.children]) {
      if (obj.userData?.isGraphContent) this.scene.remove(obj);
    }
    this.nodeMeshes = [];

    const nodeGroup = new THREE.Group();
    nodeGroup.userData.isGraphContent = true;

    for (const node of graph.nodes) {
      const pos = layout.positionOf(node.id);
      if (!pos) continue;
      const radius = node.kind === "module" ? 1.8 : 1.0;
      const geometry = new THREE.SphereGeometry(radius, 16, 16);
      const color = colorForDisposition(node.worst_disposition);
      const material = new THREE.MeshStandardMaterial({
        color,
        emissive: color,
        emissiveIntensity: node.worst_disposition ? 0.35 : 0.08,
        roughness: 0.5,
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

    for (const edge of graph.edges) {
      if (edge.kind !== "calls") continue; // "contains" edges (module -> its functions) aren't drawn as call lines
      const from = layout.positionOf(edge.source);
      if (!from) continue;
      const to = edge.target ? layout.positionOf(edge.target) : null;
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
