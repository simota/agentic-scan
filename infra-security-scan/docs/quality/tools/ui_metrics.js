// Usage: node ui_metrics.js DEMO_EN DEMO_JA DEMO_BIG  — fixed UI measurements for the SQI rubric.
const { chromium } = require('playwright');
(async()=>{
 const [en,ja,big]=process.argv.slice(2); const b=await chromium.launch();
 // 1. Mid-word breaks in register cells and hscroll, per viewport/lang.
 for (const [dir,lang] of [[en,'en'],[ja,'ja']]) for (const w of [1280,1024,768,390,320]) {
  const p=await b.newPage({viewport:{width:w,height:900}}); await p.goto('file://'+dir+'/dashboard.html');
  const r=await p.evaluate(()=>{const out=[];
   document.querySelectorAll('table.register tr.row td, .perspective .st, .pill').forEach(td=>{
    const tw=document.createTreeWalker(td,NodeFilter.SHOW_TEXT);let n;
    while((n=tw.nextNode())){const re=/[A-Za-z]{4,}/g;let m;while((m=re.exec(n.data))){
      const rg=document.createRange();rg.setStart(n,m.index);rg.setEnd(n,m.index+m[0].length);
      const tops=new Set([...rg.getClientRects()].map(x=>Math.round(x.top)));if(tops.size>1)out.push(m[0]);}}});
   return {breaks:out, hscroll:document.documentElement.scrollWidth-innerWidth};});
  console.log(`layout ${lang} ${w}px hscroll=${r.hscroll} midword=${r.breaks.length} ${JSON.stringify([...new Set(r.breaks)])}`);
  await p.close();
 }
 // 2. States.
 const p=await b.newPage({viewport:{width:1280,height:900}}); await p.goto('file://'+en+'/dashboard.html');
 const theme0=await p.getAttribute('#theme','aria-pressed'); await p.click('#theme'); const theme1=await p.getAttribute('#theme','aria-pressed');
 await p.fill('#f-q','zzzz-no-match');
 const nomatch=await p.evaluate(()=>{const e=[...document.querySelectorAll('tbody tr')].filter(r=>!r.hidden&&r.offsetParent);return e.map(r=>r.innerText.trim()).join('|');});
 const clear=await p.$('tbody button.clear-filters');
 let recoverSteps='n/a (no control)';
 if(clear){await clear.click();recoverSteps='1 action; rows visible='+await p.evaluate(()=>[...document.querySelectorAll('tr.row')].filter(r=>!r.hidden).length)+'; focus='+await p.evaluate(()=>document.activeElement.id||document.activeElement.tagName);}
 console.log(`states theme aria-pressed before=${theme0} after=${theme1}; no-match visible row="${nomatch}"; recovery=${recoverSteps}`);
 // 3. Filter latency on 1000+ findings (median of 15 inputs).
 const q=await b.newPage({viewport:{width:1280,height:900}}); const t0=Date.now(); await q.goto('file://'+big+'/dashboard.html'); const load=Date.now()-t0;
 const lat=await q.evaluate(async()=>{const i=document.getElementById('f-q'),xs=[];for(let k=0;k<15;k++){i.value=k%2?'flow':'zz'+k;const t=performance.now();i.dispatchEvent(new Event('input'));document.body.offsetHeight;xs.push(performance.now()-t);}xs.sort((a,b)=>a-b);return xs[7];});
 const cls=await q.evaluate(()=>new Promise(r=>{let s=0;new PerformanceObserver(l=>{l.getEntries().forEach(e=>{if(!e.hadRecentInput)s+=e.value;});}).observe({type:'layout-shift',buffered:true});setTimeout(()=>r(s),300);}));
 console.log(`perf big(${await q.evaluate(()=>document.querySelectorAll('tr.row').length)} rows) load=${load}ms filter-median=${lat.toFixed(1)}ms CLS=${cls.toFixed(4)}`);
 await b.close();})();
