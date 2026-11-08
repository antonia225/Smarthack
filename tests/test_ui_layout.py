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


def test_details_replace_placeholder_and_results_use_page_scroll(browser, server):
    page = _page(browser, server)
    assert page.is_visible("#page-home .unselected-device")
    assert page.locator("#page-home .overview").count() == 0
    document_rect = "e => { const r = e.getBoundingClientRect(); return [r.x, r.y + scrollY, r.width, r.height]; }"
    graph_before = page.locator("#page-home .nv-graf").evaluate(document_rect)
    page.click("#page-home .vrow >> nth=0")
    assert _open(page) == "true"
    assert page.locator("#page-home .nv-graf").evaluate(document_rect) == graph_before
    for selector in [".vlist", ".insp-body"]:
        assert page.locator("#page-home " + selector).evaluate("e => getComputedStyle(e).overflowY") == "visible"
    page.keyboard.press("Escape")
    assert page.is_visible("#page-home .unselected-device")


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


def test_device_list_opens_the_same_details_with_keyboard(browser, server):
    page = _page(browser, server)
    page.click("#page-home .view-opt >> nth=1")
    assert page.is_hidden("#page-home .graph")
    assert page.is_hidden("#page-home .map-tools")
    assert page.locator("#page-home .nv-graf-head .view-picker").count() == 1
    device = page.locator("#page-home .device-item").nth(1)
    device.focus()
    page.keyboard.press("Enter")
    page.wait_for_selector('#page-home .inspector[data-open="true"]')
    assert _open(page) == "true"
    page.keyboard.press("Escape")
    assert _open(page) == "false"
    assert device.evaluate("e => e === document.activeElement")


def test_mobile_details_are_inline_and_leave_navigation_available(browser, server):
    page = _page(browser, server, 390, 844)
    page.locator("#page-home .node[role=button]").first.focus()
    page.keyboard.press("Enter")
    panel = page.locator("#page-home .inspector")
    assert panel.get_attribute("aria-modal") is None
    assert not page.locator(".sidebar").evaluate("e => e.inert")
    assert panel.locator(".insp-body").evaluate("e => getComputedStyle(e).overflowY") == "visible"
    page.keyboard.press("Escape")
    assert page.is_visible("#page-home .unselected-device")


def test_language_switch_updates_the_new_summary_and_device_views(browser, server):
    page = _page(browser, server)
    page.click("#lang-en")
    assert page.locator("html").get_attribute("lang") == "en"
    assert page.inner_text("#home-title") == "Care for your network."
    assert page.text_content("#page-home .unselected-device h2") == "No device selected"
    assert page.inner_text("#page-home .view-opt >> nth=1") == "List"
    page.click("#lang-ro")
    assert page.inner_text("#page-home .view-opt >> nth=1") == "Listă"


def test_map_zoom_pan_and_reset_with_keyboard(browser, server):
    page = _page(browser, server)
    graph = page.locator("#page-home .graph")
    svg = graph.locator("svg.map")
    original = svg.get_attribute("viewBox")
    graph.focus()
    page.keyboard.press("+")
    zoomed = svg.get_attribute("viewBox")
    assert zoomed != original
    page.keyboard.press("ArrowRight")
    assert svg.get_attribute("viewBox") != zoomed
    page.keyboard.press("0")
    assert svg.get_attribute("viewBox") == original
    page.click("#page-home .map-tools button >> nth=2")
    assert svg.get_attribute("viewBox") != original
    page.click("#page-home .map-tools button >> nth=1")
    assert svg.get_attribute("viewBox") == original


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


@pytest.mark.parametrize("width", [1440, 1024, 768, 390])
def test_import_detail_has_no_implicit_grid_columns(browser, server, width):
    page = _page(browser, server, width=width)
    page.click(".nav-item[data-page=import]")
    page.set_input_files("#page-import input[type=file]", str(VALIDATION / "V3_small_office.xml"))
    page.click("#page-import .file-card")
    page.wait_for_selector("#page-import .node")
    layout = page.eval_on_selector("#page-import .nv", """e => {
      const css = getComputedStyle(e), bounds = e.getBoundingClientRect();
      const graph = e.querySelector('.nv-graf').getBoundingClientRect();
      return { columns: css.gridTemplateColumns.split(' ').length,
        areas: css.gridTemplateAreas, width: bounds.width, graphWidth: graph.width,
        overflow: document.documentElement.scrollWidth > window.innerWidth };
    }""")
    assert layout["columns"] == (2 if width >= 900 else 1), layout
    assert 'score' in layout["areas"] and 'detail' in layout["areas"], layout
    assert layout["graphWidth"] > layout["width"] * (0.4 if width >= 900 else 0.95), layout
    assert not layout["overflow"], layout
    page.context.close()


@pytest.mark.parametrize("width,height", [(1280, 800), (1440, 900), (390, 844)])
def test_import_detail_keeps_its_grid(browser, server, width, height):
    page = _page(browser, server, width, height)
    page.click(".nav-item[data-page=import]")
    page.set_input_files("#page-import input[type=file]", [str(VALIDATION / "V2_smart_home.xml")])
    page.click("#page-import .file-card >> nth=0")
    page.wait_for_selector("#page-import .node", timeout=10000)
    areas = page.eval_on_selector("#page-import .nv", "e => getComputedStyle(e).gridTemplateAreas")
    assert "score" in areas and "detail" in areas
    for selector in [".nv-graf", ".nv-vuln", ".nv-lateral", ".inspector"]:
        assert page.eval_on_selector("#page-import " + selector, RECT)[2] >= 300
    assert page.evaluate("document.documentElement.scrollHeight") < 2600
