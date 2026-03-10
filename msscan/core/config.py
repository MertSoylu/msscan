"""Scan configuration — speed profiles, config loading, TOML support."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class SpeedProfile(Enum):
    """Predefined speed profiles controlling rate and concurrency."""

    STEALTH = "stealth"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"


# Default settings for each speed profile
PROFILE_DEFAULTS: dict[str, dict[str, Any]] = {
    "stealth": {
        "rate_limit": 2,
        "concurrency": 1,
        "jitter": (1.0, 3.0),
    },
    "normal": {
        "rate_limit": 10,
        "concurrency": 5,
        "jitter": (0.0, 0.0),
    },
    "aggressive": {
        "rate_limit": 50,
        "concurrency": 20,
        "jitter": (0.0, 0.0),
    },
}


@dataclass
class ScanConfig:
    """Complete scan configuration resolved from all sources."""

    targets: list[str] = field(default_factory=list)
    modules: list[str] = field(default_factory=lambda: ["all"])
    speed_profile: SpeedProfile = SpeedProfile.NORMAL
    rate_limit: int = 10
    timeout: float = 10.0
    max_response_size: int = 5_000_000  # 5 MB
    retry_count: int = 3
    cache_enabled: bool = True
    output_formats: list[str] = field(default_factory=lambda: ["console"])
    output_paths: dict[str, str] = field(default_factory=dict)
    fail_on: list[str] = field(default_factory=lambda: ["HIGH", "CRITICAL"])
    config_file: Path | None = None

    def apply_profile(self) -> None:
        """Apply speed profile defaults if rate_limit was not explicitly set."""
        profile_settings = PROFILE_DEFAULTS.get(self.speed_profile.value, {})
        if "rate_limit" in profile_settings:
            self.rate_limit = profile_settings["rate_limit"]

    @property
    def concurrency(self) -> int:
        """Return concurrency level from current profile."""
        profile_settings = PROFILE_DEFAULTS.get(self.speed_profile.value, {})
        return profile_settings.get("concurrency", 5)

    @property
    def jitter(self) -> tuple[float, float]:
        """Return jitter range from current profile."""
        profile_settings = PROFILE_DEFAULTS.get(self.speed_profile.value, {})
        return profile_settings.get("jitter", (0.0, 0.0))


def _load_toml(path: Path) -> dict[str, Any]:
    """Load a TOML file, using tomllib (3.11+) or tomli."""
    text = path.read_text(encoding="utf-8")
    if sys.version_info >= (3, 11):
        import tomllib
        return tomllib.loads(text)
    try:
        import tomli
        return tomli.loads(text)
    except ImportError:
        return {}


def _find_config_files() -> list[Path]:
    """Return config file paths in resolution order (lowest to highest priority)."""
    candidates: list[Path] = []

    # User-level config
    if os.name == "nt":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            candidates.append(Path(appdata) / "msscan" / "config.toml")
    else:
        candidates.append(Path.home() / ".config" / "msscan" / "config.toml")

    # Project-level config
    candidates.append(Path.cwd() / "msscan.toml")

    return [p for p in candidates if p.exists()]


def load_config(
    cli_overrides: dict[str, Any] | None = None,
    config_path: Path | None = None,
) -> ScanConfig:
    """Load configuration from files and CLI overrides.

    Resolution order (lowest to highest priority):
    1. Built-in defaults (ScanConfig defaults)
    2. User-level config file (~/.config/msscan/config.toml)
    3. Project-level config file (./msscan.toml)
    4. Explicit config file (--config flag)
    5. Environment variables (MSSCAN_*)
    6. CLI arguments
    """
    config = ScanConfig()
    merged: dict[str, Any] = {}

    # Load config files
    config_files = _find_config_files()
    if config_path and config_path.exists():
        config_files.append(config_path)

    for cfg_file in config_files:
        data = _load_toml(cfg_file)
        if "scan" in data:
            merged.update(data["scan"])
        config.config_file = cfg_file

    # Environment variables
    env_map = {
        "MSSCAN_RATE_LIMIT": ("rate_limit", int),
        "MSSCAN_TIMEOUT": ("timeout", float),
        "MSSCAN_PROFILE": ("speed_profile", lambda v: SpeedProfile(v)),
        "MSSCAN_MODULES": ("modules", lambda v: v.split(",")),
    }
    for env_key, (attr, cast) in env_map.items():
        env_val = os.environ.get(env_key)
        if env_val is not None:
            try:
                merged[attr] = cast(env_val)
            except (ValueError, KeyError):
                pass

    # CLI overrides (highest priority)
    if cli_overrides:
        merged.update(cli_overrides)

    # Apply merged values to config
    for key, value in merged.items():
        if hasattr(config, key):
            setattr(config, key, value)

    return config


def generate_config_template() -> str:
    """Return a TOML config template string."""
    return '''\
# msscan configuration file
# Place this file at ./msscan.toml or ~/.config/msscan/config.toml

[scan]
modules = ["xss", "sqli", "csrf", "open_redirect", "ssrf", "headers", "subdomain"]
profile = "normal"
timeout = 10.0

[output]
formats = ["console"]
# json_path = "./msscan-results.json"
# html_path = "./msscan-report.html"
# sarif_path = "./msscan-results.sarif"
fail_on = ["HIGH", "CRITICAL"]

[profile.stealth]
rate_limit = 2
concurrency = 1
jitter = [1.0, 3.0]

[profile.normal]
rate_limit = 10
concurrency = 5

[profile.aggressive]
rate_limit = 50
concurrency = 20
'''
