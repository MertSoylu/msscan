"""Plugin discovery — find scanner modules via entry points and local directory."""

from __future__ import annotations

import importlib
import importlib.metadata
import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from msscan.scanners.base import BaseScanner

logger = logging.getLogger("msscan.plugins")

# Built-in scanner module paths (fallback when entry points are not registered)
BUILTIN_SCANNERS: dict[str, str] = {
    "xss": "msscan.scanners.xss",
    "sqli": "msscan.scanners.sqli",
    "csrf": "msscan.scanners.csrf",
    "open_redirect": "msscan.scanners.open_redirect",
    "ssrf": "msscan.scanners.ssrf",
    "headers": "msscan.scanners.headers",
    "subdomain": "msscan.scanners.subdomain",
}

# User plugin directory
_PLUGIN_DIR = Path.home() / ".msscan" / "plugins"


def discover_scanners() -> dict[str, type["BaseScanner"]]:
    """Discover all available scanner classes from multiple sources.

    Sources (checked in order, later sources override earlier):
    1. Built-in scanner modules
    2. Entry points (group: msscan.scanners)
    3. Local plugin directory (~/.msscan/plugins/*.py)
    """
    scanners: dict[str, type["BaseScanner"]] = {}

    # 1. Built-in scanners
    for name, module_path in BUILTIN_SCANNERS.items():
        try:
            mod = importlib.import_module(module_path)
            scanner_cls = getattr(mod, "Scanner", None)
            if scanner_cls is not None:
                scanners[name] = scanner_cls
        except Exception as exc:
            logger.warning("Failed to load built-in scanner '%s': %s", name, exc)

    # 2. Entry points
    try:
        eps = importlib.metadata.entry_points()
        # Python 3.12+ returns a SelectableGroups, older versions return dict
        if hasattr(eps, "select"):
            scanner_eps = eps.select(group="msscan.scanners")
        else:
            scanner_eps = eps.get("msscan.scanners", [])  # type: ignore[assignment]

        for ep in scanner_eps:
            try:
                scanner_cls = ep.load()
                if hasattr(scanner_cls, "name") and hasattr(scanner_cls, "scan"):
                    scanners[ep.name] = scanner_cls
                else:
                    logger.warning(
                        "Entry point '%s' does not define a valid Scanner class", ep.name
                    )
            except Exception as exc:
                logger.warning("Failed to load entry point '%s': %s", ep.name, exc)
    except Exception:
        pass  # entry_points may not be available in all environments

    # 3. Local plugin directory
    if _PLUGIN_DIR.is_dir():
        for py_file in sorted(_PLUGIN_DIR.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(
                    f"msscan_plugin_{py_file.stem}", py_file
                )
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    scanner_cls = getattr(mod, "Scanner", None)
                    if scanner_cls is not None and hasattr(scanner_cls, "scan"):
                        name = getattr(scanner_cls, "name", py_file.stem)
                        scanners[name] = scanner_cls
                    else:
                        logger.warning(
                            "Plugin '%s' does not define a Scanner class", py_file.name
                        )
            except Exception as exc:
                logger.warning("Failed to load plugin '%s': %s", py_file.name, exc)

    return scanners


def load_scanner(name: str) -> "BaseScanner":
    """Load and instantiate a scanner by name."""
    scanners = discover_scanners()
    if name not in scanners:
        raise ValueError(f"Unknown scanner: {name!r}")
    return scanners[name]()


def list_available_scanners() -> list[dict[str, str]]:
    """Return metadata about all available scanners."""
    result = []
    for name, cls in sorted(discover_scanners().items()):
        scanner = cls()
        result.append({
            "name": name,
            "description": getattr(scanner, "description", "") or "",
            "version": getattr(scanner, "version", "unknown"),
            "source": _get_scanner_source(name, cls),
        })
    return result


def _get_scanner_source(name: str, cls: type) -> str:
    """Determine if a scanner is built-in, entry-point, or local plugin."""
    module = cls.__module__
    if module.startswith("msscan.scanners."):
        return "built-in"
    if module.startswith("msscan_plugin_"):
        return "local"
    return "entry-point"
