import {test, expect} from '@playwright/test';
import {readFile, mkdir, writeFile} from 'node:fs/promises';
import {join} from 'node:path';

const graph={target_repository:'paired-path-investigation',nodes:[
  {id:'src',kind:'module',file_path:'src/entry.ts'},
  ...['request','helper','sink','disconnected'].map(id=>({id:`src.${id}`,kind:'function',file_path:'src/entry.ts',lineno:4})),
],edges:[
  ...['request','helper','sink','disconnected'].map(id=>({source:'src',target:`src.${id}`,kind:'contains'})),
  {source:'src.request',target:'src.helper',kind:'calls',resolved:true,lineno:4},
  {source:'src.helper',target:'src.sink',kind:'calls',resolved:true,lineno:8},
  {source:'src.disconnected',target:null,kind:'calls',resolved:false,unresolved_reason:'dynamic dispatch'},
],coverage:{collected_files:3,parsed_files:2,warnings:[{kind:'parse_failures',detail:'one unsupported syntax'}]}};
async function upload(page,data){await page.locator('#file-input').setInputFiles({name:'graph.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(data))});}
const ids=page=>page.evaluate(()=>window.__sentinelZeroViewer.scene.nodeMeshes.map(m=>m.userData.nodeId).sort());

test('coverage, original paths, collapse, search and two-hop navigation',async({page})=>{
  await page.goto('/'); await expect(page.locator('#stats')).not.toBeEmpty();
  await upload(page,graph);
  await page.getByText('Coverage and limitations',{exact:true}).click();
  await expect(page.locator('#coverage')).toContainText('2 parsed / 3 collected');
  await expect(page.locator('#coverage')).toContainText('parse_failures');
  await expect(page.locator('#coverage')).toContainText('attached proof: 0');
  await page.evaluate(()=>window.__sentinelZeroViewer.scene.select('src'));
  await page.getByRole('button',{name:'Collapse module',exact:true}).click();
  await expect.poll(()=>ids(page)).toEqual(['src']);
  await page.locator('#search-input').fill('src.request');
  await expect.poll(()=>ids(page)).toEqual(['src.request']);
  await page.locator('#reset-filter-btn').click();
  await page.locator('#view-mode').selectOption('investigation');
  await page.evaluate(()=>window.__sentinelZeroViewer.scene.select('src.request'));
  await expect.poll(()=>ids(page)).toEqual(['src.helper','src.request']);
  await page.locator('#hops').selectOption('2');
  await expect.poll(()=>ids(page)).toEqual(['src.helper','src.request','src.sink']);
  await page.locator('#inspector button').filter({hasText:'src.helper'}).click();
  await expect(page.locator('#inspector h2')).toHaveText('src.helper');
  await expect(page.locator('#inspector')).toContainText('Evidence unavailable');
  const edges=await page.evaluate(()=>window.__sentinelZeroViewer.scene.renderedEdges);
  for(const edge of edges) expect(graph.edges[edge.originalIndex].resolved).toBe(true);
  await upload(page,{...graph,coverage:{warnings:[{kind:'module_identity_disambiguated'}]}});
  await page.locator('#compare-input').setInputFiles({name:'baseline.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(graph))});
  await expect(page.locator('#compare-summary')).toContainText('Identity migration warning');
});

test('Next.js focus artifact renders without inventing independent proof; record actual timings',async({page})=>{
  test.skip(!process.env.SENTINEL_STUDIO_FOCUS,'Set SENTINEL_STUDIO_FOCUS for local real-artifact validation');
  const focus=JSON.parse(await readFile(process.env.SENTINEL_STUDIO_FOCUS,'utf8'));
  expect(focus.nodes).toHaveLength(182);
  const errors=[]; page.on('pageerror',e=>errors.push(e.message));
  await page.goto('/'); await expect(page.locator('#stats')).not.toBeEmpty();
  const started=performance.now(); await upload(page,focus);
  await expect(page.locator('#stats')).toContainText('182 nodes');
  await expect.poll(()=>ids(page)).toHaveLength(182);
  const loadMs=performance.now()-started;
  const selected=focus.nodes.find(n=>n.kind==='function');
  const t=performance.now(); await page.evaluate(id=>window.__sentinelZeroViewer.scene.select(id),selected.id);
  await expect(page.locator('#inspector h2')).toHaveText(selected.id);
  const selectMs=performance.now()-t;
  await page.getByText('Coverage and limitations',{exact:true}).click();
  await expect(page.locator('#coverage')).toContainText('attached proof: 0');
  if(process.env.SENTINEL_STUDIO_ARTIFACTS){
    await mkdir(process.env.SENTINEL_STUDIO_ARTIFACTS,{recursive:true});
    await page.screenshot({path:join(process.env.SENTINEL_STUDIO_ARTIFACTS,'studio-nextjs.png')});
    const counts=await page.evaluate(()=>({nodes:window.__sentinelZeroViewer.scene.nodeMeshes.length,edges:window.__sentinelZeroViewer.scene.renderedEdges.length}));
    await writeFile(join(process.env.SENTINEL_STUDIO_ARTIFACTS,'browser-timings.json'),JSON.stringify({nodes:focus.nodes.length,sourceEdges:focus.edges.length,visible:counts,loadMs,selectMs,environment:'Headless Chromium / SwiftShader; local fixture run, not a production performance guarantee'},null,2));
  }
  expect(errors).toEqual([]);
});
