// Usage: AXE=/path/axe.min.js node axe_check.js DEMO_DIR... — axe-core WCAG 2.x A/AA + best-practice on both reports, light and dark, details expanded.
const { chromium } = require('playwright');
const fs=require('fs');
const axe=fs.readFileSync(process.env.AXE || require.resolve('axe-core/axe.min.js'),'utf8');
(async()=>{
 const b=await chromium.launch();
 for (const dir of process.argv.slice(2)) for (const file of ['dashboard.html','assessment.html']) for (const scheme of ['light','dark']) {
  const p=await b.newPage({colorScheme:scheme});
  await p.goto('file://'+dir+'/'+file);
  // open all details for coverage
  if(file==='dashboard.html') await p.evaluate(()=>document.querySelectorAll('.finding-toggle').forEach(b=>b.click()));
  await p.addScriptTag({content:axe});
  const r=await p.evaluate(async()=>{const r=await axe.run(document,{runOnly:['wcag2a','wcag2aa','wcag21aa','wcag22aa','best-practice']});return r.violations.map(v=>({id:v.id,impact:v.impact,n:v.nodes.length,ex:v.nodes.slice(0,3).map(n=>n.target.join(' ')+' | '+(n.any[0]&&n.any[0].message||''))}));});
  console.log('##',dir.split('/').pop(),file,scheme,'violations:',r.length, 'nodes:', r.reduce((a,v)=>a+v.n,0));
  r.forEach(v=>console.log('  ',v.id,v.impact,v.n,JSON.stringify(v.ex)));
 }
 await b.close();
})();
