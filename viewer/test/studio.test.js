import {test} from 'node:test';
import assert from 'node:assert/strict';
import {ForceLayout3D} from '../src/layout.js';
import {validateGraphDocument, GraphValidationError} from '../src/graphLoader.js';
import {architecture, neighborhood, projectGraph} from '../src/studioModel.js';
import {diffGraphs} from '../src/diff.js';

const graph = {
  nodes: [{id:'a',kind:'module',file_path:'src/a.ts'}, {id:'b',kind:'module',file_path:'src/b.ts'},
    ...['a.entry','a.helper','b.sink','b.control'].map(id=>({id,kind:'function'}))],
  edges: [
    ...['a.entry','a.helper','b.sink','b.control'].map(id=>({source:id[0],target:id,kind:'contains'})),
    {source:'a.entry',target:'a.helper',kind:'calls',resolved:true},
    {source:'a.helper',target:'b.sink',kind:'calls',resolved:true},
    {source:'b.control',target:'b.sink',kind:'calls',resolved:false,unresolved_reason:'dynamic'},
  ],
};
test('coverage survives validation without modifying original nodes or edges',()=>{
  const coverage={collected_files:2,parsed_files:1,warnings:[{kind:'parse_failures',detail:'not analyzed'}]};
  const doc=validateGraphDocument({...graph,coverage});
  assert.equal(doc.coverage,coverage); assert.equal(doc.nodes,graph.nodes); assert.equal(doc.edges,graph.edges);
  assert.equal(validateGraphDocument(graph).coverage,null);
});
test('duplicates, conflicting containment, invalid coverage and missing sources fail visibly',()=>{
  for(const doc of [
    {...graph,nodes:[...graph.nodes,graph.nodes[0]]},
    {...graph,edges:[...graph.edges,{source:'b',target:'a.entry',kind:'contains'}]},
    {...graph,coverage:{warnings:'no'}}, {...graph,coverage:{parsed_files:-1}},
    {...graph,edges:[{source:'missing',target:'a',kind:'calls',resolved:true}]},
  ]) assert.throws(()=>validateGraphDocument(doc),GraphValidationError);
});
test('layout and grouping repeat identically even if source ordering changes',()=>{
  const a=new ForceLayout3D(graph.nodes,graph.edges);
  const b=new ForceLayout3D([...graph.nodes].reverse(),[...graph.edges].reverse());
  for(const n of graph.nodes) assert.deepEqual(a.positionOf(n.id),b.positionOf(n.id));
  const model=architecture(graph); assert.equal(model.parent.get('a.entry'),'a');
  assert.deepEqual(model.groups.get('src'),['a','b']); assert.equal(model.degree.get('a.helper'),2);
});
test('bounded paths use only recorded resolved edges and leave control disconnected',()=>{
  assert.deepEqual([...neighborhood(graph,'a.entry',1)].sort(),['a.entry','a.helper']);
  assert.deepEqual([...neighborhood(graph,'a.entry',2)].sort(),['a.entry','a.helper','b.sink']);
  const p=projectGraph(graph,{investigation:true,selected:'a.entry',hops:2});
  assert.equal(p.nodes.some(n=>n.id==='b.control'),false);
  for(const e of p.edges) assert.deepEqual(graph.edges[e.originalIndex],Object.fromEntries(Object.entries(e).filter(([k])=>!['originalIndex','displayOnly'].includes(k))));
});
test('collapse is reversible and aggregates cite original edge indices',()=>{
  const before=JSON.stringify(graph);
  const p=projectGraph(graph,{collapsed:new Set(['a','b'])});
  assert.equal(p.nodes.length,2);
  const aggregate=p.edges.find(e=>e.kind==='aggregate' && e.resolved);
  assert.deepEqual(aggregate.originalIndices,[5]); assert.equal(aggregate.displayOnly,true);
  assert.equal(JSON.stringify(graph),before); assert.equal(projectGraph(graph).nodes.length,6);
});
test('identity migration is flagged and never remapped silently',()=>{
  const old={nodes:[{id:'foo',kind:'module'}]};
  const current={nodes:[{id:'file://foo.js',kind:'module'}],coverage:{warnings:[{kind:'module_identity_disambiguated'}]}};
  const d=diffGraphs(current,old); assert.equal(d.identityWarnings.length,1);
  assert.equal(d.newCount,1); assert.equal(d.removedNodes[0].id,'foo');
});
test('partial focus containment is retained with an explicit limitation, never invented nodes',()=>{
  const doc=validateGraphDocument({nodes:[{id:'module',kind:'module'}],edges:[{source:'module',target:'omitted.fn',kind:'contains'}]});
  assert.equal(doc.validationWarnings.length,1);
  const p=projectGraph(doc); assert.equal(p.nodes.length,1); assert.equal(p.edges.length,1);
  assert.equal(p.edges[0].originalIndex,0); assert.equal(p.edges[0].target,'omitted.fn');
});
