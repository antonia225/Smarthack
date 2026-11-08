"""Real-browser checks of the web UI (Playwright + the system Chrome).

Skipped automatically when Playwright or Chrome is missing. Nothing here fakes UI data:
scans are written to a temporary database the same way the app writes them, and the page
picks them up through its normal polling.
"""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

playwright_sync = pytest.importorskip("playwright.sync_api")

ROOT = Path(__file__).resolve().parent.parent
VALIDATION = ROOT / "tests" / "validation"
BOXES = (".sidebar", ".nv-graf", ".nv-vuln", ".nv-lateral")


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _save(db, name, source="live"):
    from netcheck import history
    from netcheck.scoring import analyze_file
    analysis = analyze_file(VALIDATION / name)
    analysis["source"] = source
    return history.save_scan(analysis, db)


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    db = tmp_path_factory.mktemp("ui") / "ui.db"
    _save(db, "V6a_before.xml")
    _save(db, "V2_smart_home.xml")
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "netcheck.api:app", "--port", str(port), "--log-level", "warning"],
        cwd=ROOT, env={**os.environ, "NETCHECK_DB": str(db)})
    try:
        for _ in range(60):
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                break
            except OSError:
                time.sleep(0.2)
        yield {"url": f"http://127.0.0.1:{port}/", "db": db}
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.fixture(scope="module")
def browser():
    with playwright_sync.sync_playwright() as p:
        try:
            b = p.chromium.launch(channel="chrome")
        except Exception:
            try:
                b = p.chromium.launch()
            except Exception as exc:
                pytest.skip(f"no Chrome/Chromium available: {exc}")
        yield b
        b.close()


CLS = ("window.__cls = 0; new PerformanceObserver(l => { for (const e of l.getEntries()) "
       "if (!e.hadRecentInput) window.__cls += e.value; }).observe({type: 'layout-shift', buffered: true});")
RECT = "e => { const r = e.getBoundingClientRect(); return [r.x, r.y, r.width, r.height]; }"


def _page(browser, server, width=1440, height=900, scheme="light"):
    ctx = browser.new_context(viewport={"width": width, "height": height}, color_scheme=scheme)
    page = ctx.new_page()
    page.add_init_script(CLS)
    page.goto(server["url"])
    page.wait_for_selector("#page-home .node", timeout=10000)
    page.wait_for_timeout(300)
    return page


def _boxes(page):
    return {sel: page.eval_on_selector(f"#page-home {sel}" if sel != ".sidebar" else sel, RECT) for sel in BOXES}


def _open(page):
    return page.eval_on_selector("#page-home .inspector", "e => e.dataset.open")


def test_panel_never_reflows_the_grid_at_1440x900(browser, server):
    page = _page(browser, server)
    assert page.evaluate("document.documentElement.scrollHeight <= window.innerHeight")
    before, cls_before = _boxes(page), page.evaluate("window.__cls")
    page.click("#page-home .vrow >> nth=0")
    page.wait_for_timeout(300)
    opened = _boxes(page)
    assert _open(page) == "true"
    insp = page.eval_on_selector("#page-home .inspector", RECT)
    assert insp == before[".nv-lateral"]
    page.keyboard.press("Escape")
    page.wait_for_timeout(300)
    assert _open(page) == "false"
    closed = _boxes(page)
    assert opened == before and closed == before
    assert page.evaluate("window.__cls") - cls_before == 0


def test_text_is_at_least_16px_and_hostnames_never_shown(browser, server):
    page = _page(browser, server)
    small = page.evaluate("""() => { const bad = [];
      const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      while (walk.nextNode()) { const n = walk.currentNode; if (!n.textContent.trim()) continue;
        const e = n.parentElement; if (!e || e.closest('.sr-only, script, style, [hidden]')) continue;
        const cs = getComputedStyle(e); if (cs.display === 'none' || cs.visibility === 'hidden') continue;
        if (parseFloat(cs.fontSize) < 15.99) bad.push(e.tagName + ':' + n.textContent.trim().slice(0, 30) + ':' + cs.fontSize); }
      return bad; }""")
    assert small == []
    body = page.inner_text("body")
    for scan in json.load(urllib.request.urlopen(server["url"] + "api/scans")):
        detail = json.load(urllib.request.urlopen(f"{server['url']}api/scans/{scan['id']}"))
        for device in detail["devices"]:
            if device.get("hostname"):
                assert device["hostname"] not in body


def test_home_updates_live_without_reload(browser, server):
    page = _page(browser, server)
    page.evaluate("document.body.dataset.marker = 'same-page'")
    first = page.inner_text("#page-home .ring")
    _save(server["db"], "V6b_after.xml")
    page.wait_for_function("(t) => document.querySelector('#page-home .ring').innerText !== t", arg=first, timeout=12000)
    assert page.evaluate("document.body.dataset.marker") == "same-page"


def test_import_batch_does_not_touch_home(browser, server):
    page = _page(browser, server)
    home = page.inner_text("#page-home .ring")
    page.click(".nav-item[data-page=import]")
    page.set_input_files("#page-import input[type=file]",
                         [str(VALIDATION / "V3_small_office.xml"), str(VALIDATION / "V7_broken.xml")])
    page.click("#page-import .file-card >> nth=0"); page.wait_for_selector("#page-import .node", timeout=10000)
    page.click(".nav-item[data-page=home]")
    assert page.inner_text("#page-home .ring") == home


def test_narrow_screen_has_no_horizontal_scroll(browser, server):
    page = _page(browser, server, 390, 844)
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


def test_import_list_cards_detail_back_and_error_autodismiss(browser, server):
    page = _page(browser, server)
    page.click(".nav-item[data-page=import]")
    page.set_input_files("#page-import input[type=file]",
                         [str(VALIDATION / "V3_small_office.xml"), str(VALIDATION / "V7_broken.xml")])
    page.wait_for_selector("#page-import .file-card")
    assert page.locator("#page-import .file-card").count() == 1
    assert "V3_small_office.xml" in page.inner_text("#page-import .file-card")
    assert page.is_visible("#page-import .notice.bad")
    page.wait_for_selector("#page-import .notice.bad", state="detached", timeout=4000)
    assert page.is_visible("#page-import .btn >> text=Importă alte fișiere")
    page.click("#page-import .file-card")
    page.wait_for_selector("#page-import .node")
    assert not page.is_visible("#page-import .btn >> text=Importă alte fișiere")
    page.keyboard.press("Escape")
    assert page.is_visible("#page-import .file-card")
