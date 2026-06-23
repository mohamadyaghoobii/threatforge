"""Optional Selenium browser rendering for recon.

Renders the target in headless Chrome to capture what a real browser
sees: the post-JavaScript final URL, the rendered title, a full-page
screenshot (base64 PNG), and the rendered DOM (for tech that only loads
client-side). Entirely optional — ``is_available()`` is False when
Selenium or a browser isn't installed (e.g. most server deploys), and the
HTTP recon path still produces a full report.
"""

from __future__ import annotations

import base64
from typing import Any

_DRIVER_CACHE: dict[str, Any] = {"checked": False, "available": False}


def is_available() -> bool:
    if _DRIVER_CACHE["checked"]:
        return _DRIVER_CACHE["available"]
    _DRIVER_CACHE["checked"] = True
    try:
        import selenium  # noqa: F401
        from selenium import webdriver  # noqa: F401

        _DRIVER_CACHE["available"] = True
    except Exception:
        _DRIVER_CACHE["available"] = False
    return _DRIVER_CACHE["available"]


def _make_driver(timeout: int):
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options

    opts = Options()
    for arg in ("--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
                "--window-size=1366,900", "--ignore-certificate-errors", "--disable-extensions"):
        opts.add_argument(arg)
    opts.add_argument("--user-agent=Mozilla/5.0 (compatible; MetaSecSecurityCenter/1.0)")
    opts.page_load_strategy = "eager"
    driver = webdriver.Chrome(options=opts)
    driver.set_page_load_timeout(timeout)
    return driver


def render(url: str, timeout: int = 25) -> dict[str, Any]:
    """Return rendered details or {'rendered': False, 'error': ...}.

    Never raises — recon must continue without the browser.
    """
    if not is_available():
        return {"rendered": False, "error": "selenium/browser not available"}
    driver = None
    try:
        driver = _make_driver(timeout)
        driver.get(url)
        png = driver.get_screenshot_as_png()
        dom = driver.page_source or ""
        return {
            "rendered": True,
            "final_url": driver.current_url,
            "rendered_title": (driver.title or "")[:200],
            "dom_length": len(dom),
            "screenshot_b64": base64.b64encode(png).decode("ascii"),
            "dom": dom,
        }
    except Exception as exc:
        return {"rendered": False, "error": f"{type(exc).__name__}: {str(exc)[:200]}"}
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass
