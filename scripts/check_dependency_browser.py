"""Real built-UI acceptance with synthetic IPC; never touch native files/scanners."""
import functools
import http.server
import json
from pathlib import Path
import threading
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = r"""
const project={id:'fixture',name:'Synthetic workspace',path:'C:/fixture',isGit:false,primaryLanguage:'TypeScript',fileCount:1,lastOpenedAt:'2026-11-03',createdAt:'2026-11-03'};
const finding={id:'finding',projectId:'fixture',scanRunId:'scan',scannerId:'fixture',scannerName:'Synthetic scanner',ruleId:'fixture-rule',title:'Synthetic SQL injection',message:'Self-authored fixture, never an actual vulnerability report.',severity:'high',category:'sast',status:'new',workspaceFingerprint:'synthetic-fingerprint',location:{filePath:'src/example.ts',absolutePath:'C:/fixture/src/example.ts',logicalLocations:[],region:{startLine:2,endLine:2,startColumn:1,endColumn:10}},relatedLocations:[],codeFlows:[],cwe:['CWE-89'],fixes:[],taxa:[],rawSarif:{version:'2.1.0'},fingerprints:{exact:'synthetic'},lifecycle:{identityId:'identity',firstSeen:'2026-11-03',lastSeen:'2026-11-03',occurrenceCount:1,state:'new'},provenance:{scannerId:'fixture',scannerName:'Synthetic scanner',adapterVersion:'1',sourceFormat:'sarif',securityIrVersion:1,source:'imported',scanRunId:'scan'}};
window.__qa={calls:[],triage:[],unknown:[]};
window.__TAURI_INTERNALS__={
 transformCallback:()=>1,unregisterCallback:()=>{},
 invoke:async(command,args)=>{
  window.__qa.calls.push(command);
  switch(command){
   case 'get_project':return structuredClone(project);
   case 'get_finding':return structuredClone(finding);
   case 'finding_navigation':return {total:1,position:1};
   case 'read_source':return {path:'src/example.ts',absolutePath:'C:/fixture/src/example.ts',content:'// Synthetic source\nconst query = input;\n',language:'typescript',size:42,truncated:false};
   case 'dashboard':return {scannerCount:1,totalFindings:1};
   case 'update_triage':window.__qa.triage.push(args.update);finding.status=args.update.status;return structuredClone(finding);
   case 'recent_projects':return [];
   case 'get_setting':return null;
   default:window.__qa.unknown.push(command);throw Error('Unexpected synthetic IPC: '+command);
  }
 }
};
const constraints=[{defaultSize:62,minSize:35},{defaultSize:38,minSize:28}].map(value=>JSON.stringify(value)).sort().join(',');
localStorage.setItem('react-resizable-panels:dsw-finding-debugger',JSON.stringify({[constraints]:{layout:[58,42],expandToSizes:{}}}));
"""


class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if urlparse(self.path).path.startswith('/workspace/'):
            self.path = '/index.html'
        super().do_GET()


def main():
    output = ROOT / 'work/dependency-browser'
    output.mkdir(parents=True, exist_ok=True)
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Handler, directory=str(ROOT / 'dist')))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(viewport={'width': 1600, 'height': 1000})
            context.add_init_script(FIXTURE)
            context.route('**/*', lambda route: route.continue_() if urlparse(route.request.url).hostname in ('127.0.0.1', 'localhost', None) else route.abort())
            page = context.new_page()
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            url = f'http://127.0.0.1:{server.server_port}/workspace/fixture/findings/finding'
            page.goto(url, wait_until='networkidle')
            (output / 'initial-state.json').write_text(json.dumps({'initial_body': page.locator('body').inner_text()[:1600], 'page_errors': errors, 'ipc': page.evaluate('window.__qa')}, indent=2), encoding='utf-8')
            page.screenshot(path=str(output / 'initial.png'), full_page=True)
            expect(page.get_by_role('heading', name='Synthetic SQL injection', exact=True)).to_be_visible()
            expect(page.locator('.monaco-editor').first).to_be_visible()
            source = page.get_by_test_id('source')
            inspector = page.get_by_test_id('inspector')
            page.wait_for_function("Math.abs(document.querySelector('[data-testid=source]').getBoundingClientRect().width / (document.querySelector('[data-testid=source]').getBoundingClientRect().width + document.querySelector('[data-testid=inspector]').getBoundingClientRect().width) - .58) < .015")
            initial = source.bounding_box()['width']
            separator = page.get_by_role('separator', name='Resize source and inspector')
            box = separator.bounding_box()
            x, y = box['x'] + box['width'] / 2, box['y'] + box['height'] / 2
            page.mouse.move(x, y)
            page.mouse.down()
            page.mouse.move(x + 100, y, steps=10)
            page.mouse.up()
            page.wait_for_function("document.querySelector('[data-testid=source]').getBoundingClientRect().width > " + str(initial + 40))
            dragged = source.bounding_box()['width']
            separator.focus()
            page.keyboard.press('ArrowLeft')
            page.wait_for_function("document.querySelector('[data-testid=source]').getBoundingClientRect().width < " + str(dragged - 2))
            resized = source.bounding_box()['width']
            saved = page.evaluate("localStorage.getItem('react-resizable-panels:dsw-finding-debugger:source:inspector')")
            assert saved and 'source' in saved
            page.reload(wait_until='networkidle')
            expect(page.get_by_role('heading', name='Synthetic SQL injection', exact=True)).to_be_visible()
            page.wait_for_function("Math.abs(document.querySelector('[data-testid=source]').getBoundingClientRect().width - " + str(resized) + ") < 3")
            assert page.evaluate("localStorage.getItem('react-resizable-panels:dsw-finding-debugger')")
            page.get_by_role('button', name='Confirm', exact=True).click()
            page.wait_for_function("window.__qa.triage.length===1")
            assert page.evaluate('window.__qa.triage[0].status') == 'confirmed'
            page.get_by_role('tab', name='Trace', exact=True).click()
            expect(page.get_by_role('tab', name='Trace', exact=True)).to_have_attribute('aria-selected', 'true')
            page.screenshot(path=str(output / 'finding.png'), full_page=True)
            assert inspector.bounding_box()['width'] > 200
            assert not page.evaluate('window.__qa.unknown'), page.evaluate('window.__qa.unknown')
            page.goto(f'http://127.0.0.1:{server.server_port}/', wait_until='networkidle')
            expect(page.get_by_text('Open source', exact=True)).to_be_visible()
            assert page.locator('svg path').count() > 5
            page.screenshot(path=str(output / 'welcome.png'), full_page=True)
            assert not errors, errors
            evidence = dict(ok=True, checks=['real built React/Monaco render', 'legacy percentage layout recovery', 'actual pointer resizing', 'actual keyboard resizing', 'reload persistence', 'retained original legacy storage', 'synthetic triage mutation', 'trace tab', 'welcome SVG icons', 'zero page errors'], source_width=initial, resized_width=resized, errors=errors, limits=['Synthetic IPC only; no actual source scanning, native file access, production credentials or user data.'])
            (output / 'report.json').write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
            browser.close()
    finally:
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()
