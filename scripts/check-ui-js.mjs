import fs from 'node:fs';
import vm from 'node:vm';

const html = fs.readFileSync('crates/lazyteam-server/src/ui.html', 'utf8');
const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)];
if (!scripts.length) throw new Error('no inline scripts found in ui.html');
for (let i = 0; i < scripts.length; i++) {
  new vm.Script(scripts[i][1], { filename: `ui.html:inline-script-${i + 1}` });
}
console.log(`ui-js syntax OK (${scripts.length} inline script${scripts.length === 1 ? '' : 's'})`);
