import { loadGraphFromFile, loadGraphFromUrl, GraphValidationError } from "./graphLoader.js";
import { ForceLayout3D } from "./layout.js";
import { GraphScene } from "./scene.js";
import { diffGraphs } from "./diff.js";
import { STATUS_COLOR, DIFF_COLOR } from "./colors.js";
import { architecture, MAX_RENDER_NODES } from './studioModel.js';

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

// Reported disposition colors are separate from independently supported evidence.
const NORMAL_LEGEND = [
  { label: "VERIFIED_TRUE (reported status)", color: STATUS_COLOR.VERIFIED_TRUE, categories: ["VERIFIED_TRUE"] },
  { label: "TOOL_FAILURE", color: STATUS_COLOR.TOOL_FAILURE, categories: ["TOOL_FAILURE"] },
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
    ["File (common source root removed)", architecture(currentGraph).relativePath(node)],
  ];
  if (node.kind === "function") {
    rows.push(["Line", node.lineno ?? "—"]);
    rows.push(["Guard-shaped", node.is_guard_shaped ? "yes" : "no"]);
    rows.push(["Raises on guard", node.raises_on_guard ? "yes" : "no"]);
  }
  rows.push(["Worst disposition", node.worst_disposition ?? "(no finding attached)"]);
  rows.push(["Finding plan IDs", (node.finding_plan_ids ?? []).join(", ") || "—"]);
  rows.push(["Finding UIDs", (node.finding_uids ?? []).join(', ') || 'none attached']);
  rows.push(["Evidence", 'Evidence unavailable: no independent verification evidence is attached to this graph. A status or proximity alone is not proof.']);
  rows.push(["Resolved call connectivity", (node.kind === 'module' ? architecture(currentGraph).moduleDegree : architecture(currentGraph).degree).get(node.id) ?? 0]);
  if (node.kind === 'function') rows.push(['Containing module', architecture(currentGraph).parent.get(node.id) ?? 'Unresolved: containment relationship unavailable']);
  if (diffMode) {
    const d = scene.diffByNodeId?.get(node.id);
    if (d) rows.push(["vs. baseline", `${d.classification} (${d.oldStatus ?? "—"} → ${d.newStatus ?? "—"})`]);
  }

  inspectorEl.innerHTML =
    `<h2>${escapeHtml(node.id)}</h2><dl>` +
    rows.map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(String(value))}</dd>`).join("") +
    `</dl>`;
  if (node.kind === 'module') {
    const button = document.createElement('button'); button.className = 'btn';
    button.textContent = scene.collapsed.has(node.id) ? 'Expand module' : 'Collapse module';
    button.onclick = () => { scene.toggleModule(node.id); showInspector(node); };
    inspectorEl.append(button);
  }
  for (const [label, edges] of [
    ['Incoming', currentGraph.edges.filter(e => e.kind === 'calls' && e.target === node.id)],
    ['Outgoing', currentGraph.edges.filter(e => e.kind === 'calls' && e.source === node.id)],
  ]) {
    const title = document.createElement('h3'); title.textContent = label; inspectorEl.append(title);
    if (!edges.length) { const p = document.createElement('p'); p.textContent = 'No recorded calls'; inspectorEl.append(p); }
    edges.forEach(e => {
      const id = e.source === node.id ? e.target : e.source;
      const link = document.createElement('button'); link.className = 'btn small';
      link.textContent = `${id ?? '(unresolved)'} · ${e.resolved ? 'resolved' : 'UNRESOLVED'} · line ${e.lineno ?? '?'} · edge #${currentGraph.edges.indexOf(e)}`;
      link.title = JSON.stringify(e);
      link.disabled = !e.resolved || !currentGraph.nodes.some(n => n.id === id);
      link.onclick = () => scene.select(id); inspectorEl.append(link);
    });
  }
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
    `Visible: ${scene.nodeMeshes.length} nodes, ${scene.renderedEdges?.length ?? 0} edges (including display aggregates)`,
    `Display-only aggregates: ${scene.renderedEdges?.filter(e => e.displayOnly).length ?? 0}`,
    ...Object.entries(dispositionCounts).map(([k, v]) => `${k}: ${v}`),
  ];
  statsEl.innerHTML = lines.join("<br/>");
}
scene.onViewChange = () => { if (currentGraph) setStats(currentGraph, currentGraph.targetRepository); };

function renderCoverage(doc) {
  const el = document.getElementById('coverage');
  el.replaceChildren();
  const summary = document.createElement('p');
  const c = doc.coverage;
  summary.textContent = c && Object.keys(c).length ? `Source coverage: ${c.parsed_files ?? '?'} parsed / ${c.collected_files ?? '?'} collected. Unsupported: ${c.unsupported_files?.length ?? '?'}. Excluded declarations: ${c.excluded_declarations?.length ?? '?'}. Skipped directories: ${c.skipped_directories?.length ?? '?'}.` : 'Coverage unavailable in this export; absence of warnings is not full coverage.';
  el.append(summary);
  for (const warning of c?.warnings ?? []) {
    const p = document.createElement('p'); p.textContent = `${warning.kind}: ${warning.detail ?? ''} ${warning.path ?? ''}`; el.append(p);
  }
  if (doc.validationWarnings?.length) {
    const p = document.createElement('p');
    p.textContent = `${doc.validationWarnings.length} graph selection limitations: containment endpoints are missing. Original edges are retained as stubs; they do not establish connected paths.`; el.append(p);
    const details = document.createElement('details'), summary = document.createElement('summary'); summary.textContent = 'Missing relationship details'; details.append(summary);
    for (const message of doc.validationWarnings) { const row = document.createElement('p'); row.textContent = message; details.append(row); }
    el.append(details);
  }
  const note = document.createElement('p');
  note.textContent = 'Independently verified findings with attached proof: 0. Evidence unavailable. Graph finding counts are not independently verified vulnerability counts.'; el.append(note);
  const modules = document.getElementById('modules'); modules.replaceChildren();
  for (const [dir, ids] of [...architecture(doc).groups].sort(([a],[b]) => a < b ? -1 : 1)) {
    const group = document.createElement('details'), title = document.createElement('summary'); title.textContent = `${dir} (${ids.length})`; group.append(title);
    ids.sort().forEach(id => { const button = document.createElement('button'); button.className = 'btn small'; button.textContent = id; button.onclick = () => scene.select(id); group.append(button); });
    modules.append(group);
  }
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

function renderCompareSummary({ baselineName, newCount, changedCount, unchangedCount, removedNodes, identityWarnings = [] }) {
  compareSummaryEl.innerHTML =
    `<div>vs. <strong>${escapeHtml(baselineName)}</strong></div>` +
    `<div>${newCount} new · ${changedCount} changed · ${unchangedCount} unchanged</div>` +
    `<div>${removedNodes.length} removed from the baseline (not rendered — this view shows the CURRENT graph's layout; a removed node has nowhere to be drawn)</div>` +
    (removedNodes.length
      ? `<div class="removed-list">${removedNodes.map((n) => escapeHtml(n.id)).join("<br/>")}</div>`
      : "");
  if (identityWarnings.length) {
    const p = document.createElement('p');
    p.textContent = 'Identity migration warning: collision disambiguation can make existing files appear added/removed. IDs are preserved exactly; this comparison does not imply new vulnerabilities.';
    compareSummaryEl.prepend(p);
  }
}

async function renderGraphDocument(doc) {
  if (doc.nodes.length > MAX_RENDER_NODES) throw new GraphValidationError(`Graph has ${doc.nodes.length} nodes; default render limit is ${MAX_RENDER_NODES}. Load an explicitly selected focus graph; no nodes were silently sampled.`);
  emptyStateEl.classList.add("hidden");
  currentGraph = doc;
  diffMode = false;
  activeCategories = null;
  searchInput.value = "";
  inspectorEl.style.display = 'none';
  document.getElementById('view-mode').value = 'architecture';
  scene.investigation = false;
  clearCompareBtn.style.display = "none";
  compareSummaryEl.innerHTML = "";

  const layout = new ForceLayout3D(doc.nodes, doc.edges);
  layout.settle();
  scene.render(doc, layout);
  setStats(doc, doc.targetRepository);
  renderLegend();
  renderCoverage(doc);
}

document.getElementById('view-mode').onchange = e => scene.setMode(e.target.value === 'investigation', Number(document.getElementById('hops').value));
document.getElementById('hops').onchange = e => scene.setMode(document.getElementById('view-mode').value === 'investigation', Number(e.target.value));
document.getElementById('frame-btn').onclick = () => scene.frame();

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
    const { diffByNodeId, removedNodes, newCount, changedCount, unchangedCount, identityWarnings } = diffGraphs(currentGraph, baseline);
    diffMode = true;
    activeCategories = null;
    searchInput.value = "";
    scene.setDiff(diffByNodeId);
    scene.setFilter(null, '');
    clearCompareBtn.style.display = "inline-block";
    renderLegend();
    renderCompareSummary({ baselineName: file.name, newCount, changedCount, unchangedCount, removedNodes, identityWarnings });
  } catch (e) {
    if (e instanceof GraphValidationError) alert(`Could not load baseline '${file.name}':\n\n${e.message}`);
    else throw e;
  }
});

clearCompareBtn.addEventListener("click", () => {
  scene.clearDiff();
  diffMode = false;
  activeCategories = null;
  searchInput.value = '';
  scene.setFilter(null, '');
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
