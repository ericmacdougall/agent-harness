# Screenshots of top bar, sheet and playing at 375x667 and 390x844 (label from argv[1]); run from ~/mobile-nav on t2-dev.
import os, sys
from pathlib import Path
from playwright.sync_api import sync_playwright

label = sys.argv[1]
base = os.environ["BASE"]
password = Path(".pw").read_text().strip()
out = Path("shots-flow")
out.mkdir(exist_ok=True)
with sync_playwright() as p:
    b = p.chromium.launch(executable_path=os.environ["CHROMIUM"], args=["--ignore-certificate-errors"])
    for w, h in ((375, 667), (390, 844)):
        c = b.new_context(viewport={"width": w, "height": h}, device_scale_factor=2, is_mobile=True, has_touch=True, ignore_https_errors=True, http_credentials={"username": "eric", "password": password})
        pg = c.new_page()
        pg.set_default_timeout(4000)
        pg.goto(base + "/videos.html", wait_until="networkidle")
        pg.wait_for_timeout(1200)
        pg.screenshot(path=str(out / f"{label}-{w}x{h}-top.png"))
        try:
            pg.locator("#lesson-drawer ol button").nth(6).click()
            pg.wait_for_timeout(1200)
        except Exception:
            pass
        pg.evaluate("window.scrollTo(0,0)")
        pg.screenshot(path=str(out / f"{label}-{w}x{h}-playing.png"))
        pg.evaluate("window.scrollTo(0,500)")
        pg.wait_for_timeout(300)
        pg.screenshot(path=str(out / f"{label}-{w}x{h}-playing-scrolled.png"))
        pg.evaluate("window.scrollTo(0,0)")
        try:
            pg.locator("#lesson-drawer-toggle").click()
            pg.wait_for_timeout(500)
        except Exception:
            pass
        pg.screenshot(path=str(out / f"{label}-{w}x{h}-sheet.png"))
        c.close()
    b.close()
