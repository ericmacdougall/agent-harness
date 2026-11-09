import os
from pathlib import Path
from playwright.sync_api import sync_playwright

password = Path(".pw").read_text().strip()
with sync_playwright() as p:
    b = p.chromium.launch(executable_path=os.environ["CHROMIUM"], args=["--ignore-certificate-errors"])
    c = b.new_context(viewport={"width": 667, "height": 375}, is_mobile=True, has_touch=True, ignore_https_errors=True, http_credentials={"username": "eric", "password": password})
    pg = c.new_page()
    pg.goto(os.environ["BASE"] + "/videos.html", wait_until="networkidle")
    pg.wait_for_timeout(800)
    pg.evaluate("() => { window.__log = []; const t0 = performance.now(); const tick = () => { window.__log.push([Math.round(performance.now() - t0), Math.round(scrollY)]); if (performance.now() - t0 < 1500) requestAnimationFrame(tick); }; tick(); }")
    pg.locator("#lesson-drawer ol button").nth(5).click()
    pg.wait_for_timeout(1200)
    log = pg.evaluate("() => window.__log")
    print([x for i, x in enumerate(log) if i == 0 or x[1] != log[i - 1][1]])
    print(pg.evaluate("() => { const r = s => document.querySelector(s).getBoundingClientRect(); const v = r('.video-panel video'), b = r('.dock-bar'), h = r('.video-panel h2'), pn = r('.video-panel'); return {scrollY, vTop: v.top, vBottom: v.bottom, bBottom: b.bottom, hTop: h.top, panelTop: pn.top, barH: document.querySelector('.dock-bar').offsetHeight, docH: document.documentElement.scrollHeight}; }"))
    b.close()
