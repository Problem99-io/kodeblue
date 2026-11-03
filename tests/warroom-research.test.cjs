const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const code = fs.readFileSync(path.join(__dirname,'../internal/hub/web/warroom.js'),'utf8');
function setup() {
  let requests=0;
  const svg=(tag,attrs={})=>({tag,attrs,children:[],append(...children){this.children.push(...children);},addEventListener(){}});
  const sandbox={svg,Date,Map,Set,window:{},fetch(){requests++;throw Error('unexpected provider lookup');}};
  vm.runInNewContext(code+'\nthis.state=WAR;this.paint=paintWarResearchLinks;',sandbox);
  sandbox.state.open=true;sandbox.state.researchOpen=true;
  const now=new Date().toISOString();
  sandbox.state.researchGraph={edges:[
    {producer_id:'gateway',source_ip:'203.0.113.1',target_ip:'203.0.113.2',relation:'producer_reported_connection',last_at:now,evidence:[1]},
    {producer_id:'gateway',source_ip:'203.0.113.1',target:'fingerprint:shared',relation:'fingerprint_observed_at_source',last_at:now,evidence:[2]},
    {producer_id:'gateway',source_ip:'203.0.113.2',target:'fingerprint:shared',relation:'fingerprint_observed_at_source',last_at:now,evidence:[3]},
  ]};
  const groups=[{located:true,longitude:10,latitude:20,sources:[{ip:'203.0.113.1'}]},{located:true,longitude:30,latitude:40,sources:[{ip:'203.0.113.2'}]}];
  return {sandbox,groups,map:svg('svg'),requests:()=>requests};
}
test('map adds distinct reported connections and fingerprint similarities without lookups',()=>{
  const {sandbox,groups,map,requests}=setup();sandbox.paint(map,groups);
  assert.equal(map.children.length,1);
  const links=map.children[0].children;
  assert.equal(links.length,2);
  assert.equal(links[0].attrs.class,'research-connection');
  assert.equal(links[1].attrs.class,'research-similarity');
  assert.equal(requests(),0);
});
test('missing locations, source filtering and disabled layer do not invent map links',()=>{
  const {sandbox,groups,map}=setup();sandbox.state.server='other-server';sandbox.paint(map,groups);assert.equal(map.children[0].children.length,0);
  sandbox.state.server='';map.children=[];sandbox.paint(map,[]);assert.equal(map.children[0].children.length,0);
  sandbox.state.researchOpen=false;map.children=[];sandbox.paint(map,groups);assert.equal(map.children.length,0);
});
