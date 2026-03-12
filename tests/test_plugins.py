"""Tests for plugin discovery system."""

from __future__ import annotations

import importlib.util
from unittest.mock import patch

import pytest

from msscan.core.plugins import (
    discover_scanners,
    load_scanner,
    list_available_scanners,
    BUILTIN_SCANNERS,
)


# ---------------------------------------------------------------------------
# Built-in scanner discovery
# ---------------------------------------------------------------------------

def test_discover_builtin_scanners():
    """All 7 built-in scanners should be discovered."""
    scanners = discover_scanners()
    for name in BUILTIN_SCANNERS:
        assert name in scanners, f"Built-in scanner '{name}' not discovered"


def test_discover_scanners_have_scan_method():
    """Every discovered scanner class should have a scan method."""
    scanners = discover_scanners()
    for name, cls in scanners.items():
        assert hasattr(cls, "scan"), f"Scanner '{name}' missing scan() method"


def test_discover_scanners_have_name():
    """Every discovered scanner class should have a name attribute."""
    scanners = discover_scanners()
    for name, cls in scanners.items():
        instance = cls()
        assert hasattr(instance, "name")


# ---------------------------------------------------------------------------
# load_scanner
# ---------------------------------------------------------------------------

def test_load_scanner_by_name():
    """load_scanner should return an instantiated scanner."""
    scanner = load_scanner("xss")
    assert scanner.name == "xss"
    assert hasattr(scanner, "scan")


def test_load_scanner_unknown_raises():
    """load_scanner with unknown name should raise ValueError."""
    with pytest.raises(ValueError, match="Unknown scanner"):
        load_scanner("nonexistent_scanner_xyz")


# ---------------------------------------------------------------------------
# list_available_scanners
# ---------------------------------------------------------------------------

def test_list_available_scanners_returns_metadata():
    """list_available_scanners should return dicts with name, version, source."""
    scanners = list_available_scanners()
    assert len(scanners) >= 7
    for s in scanners:
        assert "name" in s
        assert "version" in s
        assert "source" in s
        assert s["source"] in ("built-in", "entry-point", "local")


def test_list_available_scanners_builtin_source():
    """Built-in scanners should have source='built-in'."""
    scanners = list_available_scanners()
    builtin_names = set(BUILTIN_SCANNERS.keys())
    for s in scanners:
        if s["name"] in builtin_names:
            assert s["source"] == "built-in"


# ---------------------------------------------------------------------------
# Local plugin directory
# ---------------------------------------------------------------------------

def test_discover_local_plugin(tmp_path):
    """Scanner class from a .py file in plugin dir should be discovered."""
    plugin_code = '''
from msscan.scanners.base import BaseScanner
from msscan.core.events import ScanEvent

class Scanner(BaseScanner):
    name = "test_plugin"
    description = "Test plugin scanner"
    author = "tests"
    @property
    def version(self) -> str:
        return "1.0"
    async def scan(self, ctx):
        yield  # type: ignore
'''
    plugin_file = tmp_path / "test_plugin.py"
    plugin_file.write_text(plugin_code, encoding="utf-8")

    with patch("msscan.core.plugins._PLUGIN_DIR", tmp_path):
        scanners = discover_scanners()

    assert "test_plugin" in scanners


def test_discover_skips_underscore_files(tmp_path):
    """Files starting with _ in plugin dir should be skipped."""
    (tmp_path / "_helper.py").write_text("class Scanner: pass", encoding="utf-8")

    with patch("msscan.core.plugins._PLUGIN_DIR", tmp_path):
        scanners = discover_scanners()

    # Should only have builtins, no _helper
    assert "_helper" not in scanners


def test_new_plugin_scaffold_importable(tmp_path, monkeypatch):
    """new-plugin scaffold should be importable and expose Scanner."""
    monkeypatch.setattr("msscan.core.plugins._PLUGIN_DIR", tmp_path)

    from msscan.cli.app import new_plugin

    new_plugin("sample_plugin")
    plugin_path = tmp_path / "sample_plugin.py"
    assert plugin_path.exists()

    spec = importlib.util.spec_from_file_location("sample_plugin", plugin_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert hasattr(module, "Scanner")
