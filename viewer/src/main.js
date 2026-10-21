import { loadGraphFromFile, loadGraphFromUrl, GraphValidationError } from "./graphLoader.js";
import { ForceLayout3D } from "./layout.js";
import { GraphScene } from "./scene.js";
import { diffGraphs } from "./diff.js";
import { STATUS_COLOR, DIFF_COLOR } from "./colors.js";

const container = document.getElementById("scene-container");
const statsEl = document.getElementById("stats");
const inspectorEl = document.getElementById("inspector");
const emptyStateEl = document.getElementById("empty-state");
const fileInput = document.getElementById("file-input");
const searchInput = document.getElementById("search-input");
const legendEl = document.getElementById("legend");
const isolateBtn = document.getElementById("isolate-verified-true-btn");
const resetFilterBtn = document.getElementById("reset-filter-btn");
const compareInput = document.getElementById("compare-input");
const compareSummaryEl = document.getElementById("compare-summary");
const clearCompareBtn = document.getElementById("clear-compare-btn");

// Milestone 22 legend/filter definitions. Each row is one visual swatch
// in the HUD; its `categories` are the GraphScene.categoryOf() values it
// covers -- VERIFIED_TRUE and TOOL_FAILURE share one row because they
// share one color (colors.js's STATUS_COLOR, the single source of truth
// also used by scene.js's 3D rendering -- a code-review finding caught
// these two files each hardcoding their own copy of the same colors),
// and toggling the row toggles both together.
const NORMAL_LEGEND = [
  { label: "VERIFIED_TRUE / TOOL_FAILURE", color: STATUS_COLOR.VERIFIED_TRUE, categories: ["VERIFIED_TRUE", "TOOL_FAILURE"] },
  { label: "UNRESOLVED_INCONCLUSIVE", color: STATUS_COLOR.UNRESOLVED_INCONCLUSIVE, categories: ["UNRESOLVED_INCONCLUSIVE"] },
  { label: "VERIFIED_FALSE", color: STATUS_COLOR.VERIFIED_FALSE, categories: ["VERIFIED_FALSE"] },
  { label: "no finding attached", color: STATUS_COLOR.none, categories: ["none"] },
];
const DIFF_LEGEND = [
  { label: "New since baseline", color: DIFF_COLOR.new, categories: ["new"] },
  { label: "Changed since baseline", color: DIFF_COLOR.changed, categories: ["changed"] },
  { label: "Unchanged (dim, own color)", color: DIFF_COLOR.unchanged, categories: ["unchanged"] },
];

const scene = new GraphScene(container);
scene.onNodeClick = showInspector;

let currentGraph = null; // the validated graph.json doc currently rendered
let diffMode = false;
let activeCategories = null; // Set<string> | null -- null = no filter (match GraphScene's own convention)

// Small, deliberate debug surface -- not a throwaway hack: this is what
// lets an automated smoke test (or a future dev session) drive and
// inspect the live scene without having to simulate exact pixel clicks
// against a randomized force layout. Read-only from the outside in
// practice; nothing here grants any capability main.js itself doesn't
// already have.
window.__sentinelZeroViewer = { scene, get currentGraph() { return currentGraph; } };

function escapeHtml(s) {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

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
  if (diffMode) {
    const d = scene.diffByNodeId?.get(node.id);
    if (d) rows.push(["vs. baseline", `${d.classification} (${d.oldStatus ?? "—"} → ${d.newStatus ?? "—"})`]);
  }

  inspectorEl.innerHTML =
    `<h2>${escapeHtml(node.id)}</h2><dl>` +
    rows.map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(String(value))}</dd>`).join("") +
    `</dl>`;
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

function activeLegendDefs() {
  return diffMode ? DIFF_LEGEND : NORMAL_LEGEND;
}

function allCategoriesFlat() {
  return activeLegendDefs().flatMap((row) => row.categories);
}

function renderLegend() {
  const defs = activeLegendDefs();
  legendEl.innerHTML = defs
    .map((row, i) => {
      const isActive = activeCategories === null || row.categories.some((c) => activeCategories.has(c));
      return `<div class="legend-row${isActive ? "" : " inactive"}" data-idx="${i}">` +
        `<span class="legend-dot" style="background:${row.color}"></span>${escapeHtml(row.label)}</div>`;
    })
    .join("");
  legendEl.querySelectorAll(".legend-row").forEach((rowEl) => {
    rowEl.addEventListener("click", () => toggleLegendCategory(defs[Number(rowEl.dataset.idx)].categories));
  });
}

function toggleLegendCategory(categories) {
  const all = allCategoriesFlat();
  if (activeCategories === null) activeCategories = new Set(all);
  const nowActive = categories.every((c) => activeCategories.has(c));
  for (const c of categories) {
    if (nowActive) activeCategories.delete(c);
    else activeCategories.add(c);
  }
  if (activeCategories.size === all.length) activeCategories = null; // everything active again == no filter
  applyFilter();
}

function applyFilter() {
  scene.setFilter(activeCategories, searchInput.value);
  renderLegend();
}

function renderCompareSummary({ baselineName, newCount, changedCount, unchangedCount, removedNodes }) {
  compareSummaryEl.innerHTML =
    `<div>vs. <strong>${escapeHtml(baselineName)}</strong></div>` +
    `<div>${newCount} new · ${changedCount} changed · ${unchangedCount} unchanged</div>` +
    `<div>${removedNodes.length} removed from the baseline (not rendered — this view shows the CURRENT graph's layout; a removed node has nowhere to be drawn)</div>` +
    (removedNodes.length
      ? `<div class="removed-list">${removedNodes.map((n) => escapeHtml(n.id)).join("<br/>")}</div>`
      : "");
}

async function renderGraphDocument(doc) {
  emptyStateEl.classList.add("hidden");
  currentGraph = doc;
  diffMode = false;
  activeCategories = null;
  searchInput.value = "";
  clearCompareBtn.style.display = "none";
  compareSummaryEl.innerHTML = "";

  const layout = new ForceLayout3D(doc.nodes, doc.edges);
  layout.settle();
  scene.render(doc, layout);
  setStats(doc, doc.targetRepository);
  renderLegend();
}

fileInput.addEventListener("change", async (ev) => {
  const file = ev.target.files?.[0];
  if (!file) return;
  try {
    const doc = await loadGraphFromFile(file);
    await renderGraphDocument(doc);
  } catch (e) {
    if (e instanceof GraphValidationError) alert(`Could not load '${file.name}':\n\n${e.message}`);
    else throw e;
  }
});

searchInput.addEventListener("input", applyFilter);

isolateBtn.addEventListener("click", () => {
  // "Isolate just VERIFIED_TRUE paths": matching nodes plus their direct
  // callers (GraphScene._rebuildScene's one-hop context expansion) so the
  // reachability PATH stays visible, not just disconnected dots.
  activeCategories = diffMode ? new Set(["new", "changed"]) : new Set(["VERIFIED_TRUE"]);
  applyFilter();
});

resetFilterBtn.addEventListener("click", () => {
  activeCategories = null;
  searchInput.value = "";
  applyFilter();
});

compareInput.addEventListener("change", async (ev) => {
  const file = ev.target.files?.[0];
  if (!file) return;
  if (!currentGraph) {
    alert("Load a graph.json first, then a baseline to compare it against.");
    compareInput.value = "";
    return;
  }
  try {
    const baseline = await loadGraphFromFile(file);
    const { diffByNodeId, removedNodes, newCount, changedCount, unchangedCount } = diffGraphs(currentGraph, baseline);
    diffMode = true;
    activeCategories = null;
    searchInput.value = "";
    scene.setDiff(diffByNodeId);
    clearCompareBtn.style.display = "inline-block";
    renderLegend();
    renderCompareSummary({ baselineName: file.name, newCount, changedCount, unchangedCount, removedNodes });
  } catch (e) {
    if (e instanceof GraphValidationError) alert(`Could not load baseline '${file.name}':\n\n${e.message}`);
    else throw e;
  }
});

clearCompareBtn.addEventListener("click", () => {
  scene.clearDiff();
  diffMode = false;
  activeCategories = null;
  clearCompareBtn.style.display = "none";
  compareSummaryEl.innerHTML = "";
  renderLegend();
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
