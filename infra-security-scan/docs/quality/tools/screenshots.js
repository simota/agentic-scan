// Usage: node screenshots.js DEMO_DIR TAG — full-page dashboard at 1280 light/dark and 390, plus the assessment, into ./shots/.
const { chromium } = require('playwright');
(async () => {
  const [dir, tag] = [process.argv[2], process.argv[3]];
  const b = await chromium.launch();
  for (const [name, vp, scheme] of [['desk-light',{width:1280,height:900},'light'],['desk-dark',{width:1280,height:900},'dark'],['mobile',{width:390,height:844},'light']]) {
    const p = await b.newPage({viewport: vp, colorScheme: scheme});
    const errs=[]; p.on('pageerror', e=>errs.push(e.message)); p.on('console', m=>{if(m.type()==='error')errs.push(m.text())});
    await p.goto('file://'+dir+'/dashboard.html');
    await p.screenshot({path:`shots/${tag}-${name}.png`, fullPage:true});
    const sw = await p.evaluate(()=>document.documentElement.scrollWidth - innerWidth);
    console.log(name, 'hscroll', sw, 'errors', errs);
  }
  const p = await b.newPage({viewport:{width:1280,height:900}});
  await p.goto('file://'+dir+'/assessment.html');
  await p.screenshot({path:`shots/${tag}-assessment.png`, fullPage:false});
  await b.close();
})();
