import { loadGraphFromFile, loadGraphFromUrl, GraphValidationError } from "./graphLoader.js";
import { ForceLayout3D } from "./layout.js";
import { GraphScene } from "./scene.js";

const container = document.getElementById("scene-container");
const statsEl = document.getElementById("stats");
const inspectorEl = document.getElementById("inspector");
const emptyStateEl = document.getElementById("empty-state");
const fileInput = document.getElementById("file-input");

const scene = new GraphScene(container);
scene.onNodeClick = showInspector;

// Small, deliberate debug surface -- not a throwaway hack: this is what
// lets an automated smoke test (or a future dev session) drive and
// inspect the live scene without having to simulate exact pixel clicks
// against a randomized force layout. Read-only from the outside in
// practice; nothing here grants any capability main.js itself doesn't
// already have.
window.__sentinelZeroViewer = { scene };

function showInspector(node) {
  inspectorEl.style.display = "block";
  const rows = [
    ["Kind", node.kind],
    ["File", node.file_path ?? "—"],
  ];
  if (node.kind === "function") {
    rows.push(["Line", node.lineno ?? "—"]);
    rows.push(["Guard-shaped", node.is_guard_shaped ? "yes" : "no"]);
    rows.push(["Raises on guard", node.raises_on_guard ? "yes" : "no"]);
  }
  rows.push(["Worst disposition", node.worst_disposition ?? "(no finding attached)"]);
  rows.push(["Finding plan IDs", (node.finding_plan_ids ?? []).join(", ") || "—"]);

  inspectorEl.innerHTML =
    `<h2>${escapeHtml(node.id)}</h2><dl>` +
    rows.map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(String(value))}</dd>`).join("") +
    `</dl>`;
}

function escapeHtml(s) {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

function setStats(graph, repoName) {
  const dispositionCounts = {};
  for (const n of graph.nodes) {
    const key = n.worst_disposition ?? "none";
    dispositionCounts[key] = (dispositionCounts[key] ?? 0) + 1;
  }
  const lines = [
    `<strong>${escapeHtml(repoName)}</strong>`,
    `${graph.nodes.length} nodes, ${graph.edges.length} edges`,
    ...Object.entries(dispositionCounts).map(([k, v]) => `${k}: ${v}`),
  ];
  statsEl.innerHTML = lines.join("<br/>");
}

async function renderGraphDocument(doc) {
  emptyStateEl.classList.add("hidden");
  const layout = new ForceLayout3D(doc.nodes, doc.edges);
  layout.settle();
  scene.render(doc, layout);
  setStats(doc, doc.targetRepository);
}

fileInput.addEventListener("change", async (ev) => {
  const file = ev.target.files?.[0];
  if (!file) return;
  try {
    const doc = await loadGraphFromFile(file);
    await renderGraphDocument(doc);
  } catch (e) {
    if (e instanceof GraphValidationError) {
      alert(`Could not load '${file.name}':\n\n${e.message}`);
    } else {
      throw e;
    }
  }
});

// Best-effort: try the bundled sample graph so the viewer isn't a blank
// screen on first open. Silently falls back to the empty state (no
// sample present, e.g. in a build without one bundled) -- this is NOT
// the "no silent tool failure" invariant from the analysis engine itself
// (docs/ARCHITECTURE.md S2); that invariant governs sentinel-zero's own
// findings pipeline, not this purely cosmetic first-paint convenience in
// a separate viewer tool.
loadGraphFromUrl("/sample-graph.json")
  .then(renderGraphDocument)
  .catch(() => {
    /* no sample bundled -- leave the empty state visible, prompting the file picker */
  });
