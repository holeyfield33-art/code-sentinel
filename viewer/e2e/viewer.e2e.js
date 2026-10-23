import { test, expect } from "@playwright/test";

function document(nodes) {
  return {
    target_repository: "browser-fixture",
    node_count: nodes.length,
    edge_count: 1,
    nodes,
    edges: [{ source: "mod.caller", target: "mod.sink", kind: "calls", resolved: true, lineno: 2 }],
  };
}

const current = document([
  { id: "mod", kind: "module" },
  { id: "mod.caller", kind: "function", worst_disposition: "UNRESOLVED_INCONCLUSIVE", finding_uids: ["caller"] },
  { id: "mod.sink", kind: "function", file_path: "mod.py", lineno: 3,
    worst_disposition: "VERIFIED_TRUE", finding_uids: ["sink-current"] },
  { id: "mod.new", kind: "function" },
]);
const baseline = document([
  current.nodes[0], current.nodes[1],
  { ...current.nodes[2], worst_disposition: "UNRESOLVED_INCONCLUSIVE", finding_uids: ["sink-old"] },
  { id: "mod.removed", kind: "function" },
]);

async function upload(page, selector, name, data) {
  await page.locator(selector).setInputFiles({ name, mimeType: "application/json", buffer: Buffer.from(JSON.stringify(data)) });
}

async function visibleIds(page) {
  return page.evaluate(() => window.__sentinelZeroViewer.scene.nodeMeshes.map(mesh => mesh.userData.nodeId).sort());
}

test("built viewer renders WebGL, filters with caller context, and compares uploaded graphs", async ({ page }) => {
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.goto("/");
  await expect.poll(() => page.evaluate(() => window.__sentinelZeroViewer?.scene.nodeMeshes.length ?? 0)).toBeGreaterThan(0);
  await expect.poll(() => page.evaluate(() => window.__sentinelZeroViewer.scene.renderer.info.render.triangles)).toBeGreaterThan(0);
  expect(await page.evaluate(() => window.__sentinelZeroViewer.scene.renderer.getContext().isContextLost())).toBe(false);
  await expect(page.locator("#scene-container canvas")).toBeVisible();

  await upload(page, "#file-input", "current.json", current);
  await expect(page.locator("#stats")).toContainText("4 nodes, 1 edges");
  await expect.poll(() => visibleIds(page)).toEqual(current.nodes.map(node => node.id).sort());
  await page.locator("#search-input").fill("mod.sink");
  await expect.poll(() => visibleIds(page)).toEqual(["mod.caller", "mod.sink"]);
  await page.locator("#reset-filter-btn").click();
  await expect.poll(() => visibleIds(page)).toHaveLength(4);
  await page.locator("#isolate-verified-true-btn").click();
  await expect.poll(() => visibleIds(page)).toEqual(["mod.caller", "mod.sink"]);

  const point = await page.evaluate(() => {
    const { scene } = window.__sentinelZeroViewer;
    const mesh = scene.nodeMeshes.find(item => item.userData.nodeId === "mod.sink");
    const position = mesh.position.clone().project(scene.camera);
    const rect = scene.renderer.domElement.getBoundingClientRect();
    return { x: rect.left + (position.x + 1) * rect.width / 2, y: rect.top + (1 - position.y) * rect.height / 2 };
  });
  await page.mouse.click(point.x, point.y);
  await expect(page.locator("#inspector h2")).toHaveText("mod.sink");

  await page.locator("#reset-filter-btn").click();
  await upload(page, "#compare-input", "baseline.json", baseline);
  await expect(page.locator("#compare-summary")).toContainText("1 new");
  await expect(page.locator("#compare-summary")).toContainText("1 changed");
  await expect(page.locator("#compare-summary")).toContainText("2 unchanged");
  await expect(page.locator("#compare-summary")).toContainText("mod.removed");
  expect(await page.evaluate(() => window.__sentinelZeroViewer.scene.diffByNodeId.get("mod.sink").classification)).toBe("changed");
  await page.locator("#clear-compare-btn").click();
  await expect(page.locator("#compare-summary")).toBeEmpty();
  expect(await page.evaluate(() => window.__sentinelZeroViewer.scene.diffByNodeId)).toBeNull();
  expect(errors).toEqual([]);
});

test("malformed upload is rejected while the previous scene remains visible", async ({ page }) => {
  await page.goto("/");
  await expect.poll(() => page.evaluate(() => window.__sentinelZeroViewer?.scene.nodeMeshes.length ?? 0)).toBeGreaterThan(0);
  await upload(page, "#file-input", "valid.json", current);
  await expect(page.locator("#stats")).toContainText("browser-fixture");
  const dialog = page.waitForEvent("dialog");
  await upload(page, "#file-input", "invalid.json", { nodes: null });
  const rejected = await dialog;
  expect(rejected.message()).toContain("nodes");
  await rejected.dismiss();
  await expect.poll(() => visibleIds(page)).toHaveLength(4);
  await expect(page.locator("#stats")).toContainText("browser-fixture");
});
