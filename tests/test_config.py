"""Tests for ScanConfig — TOML loading, speed profiles, config resolution."""

from __future__ import annotations

import os
from unittest.mock import patch


from msscan.core.config import (
    ScanConfig,
    SpeedProfile,
    PROFILE_DEFAULTS,
    load_config,
    generate_config_template,
)


# ---------------------------------------------------------------------------
# ScanConfig basics
# ---------------------------------------------------------------------------

def test_scan_config_defaults():
    """ScanConfig should have sensible defaults."""
    config = ScanConfig()
    assert config.speed_profile == SpeedProfile.NORMAL
    assert config.rate_limit == 10
    assert config.timeout == 10.0
    assert config.max_response_size == 5_000_000
    assert config.retry_count == 3
    assert config.cache_enabled is True


def test_speed_profile_enum_values():
    """SpeedProfile enum should have stealth, normal, aggressive."""
    assert SpeedProfile("stealth") == SpeedProfile.STEALTH
    assert SpeedProfile("normal") == SpeedProfile.NORMAL
    assert SpeedProfile("aggressive") == SpeedProfile.AGGRESSIVE


def test_profile_defaults_structure():
    """PROFILE_DEFAULTS should have entries for all profiles."""
    for profile in SpeedProfile:
        assert profile.value in PROFILE_DEFAULTS
        defaults = PROFILE_DEFAULTS[profile.value]
        assert "rate_limit" in defaults
        assert "concurrency" in defaults


def test_config_apply_profile():
    """apply_profile() should set rate_limit from profile defaults."""
    config = ScanConfig(speed_profile=SpeedProfile.STEALTH)
    config.apply_profile()
    assert config.rate_limit == 2


def test_config_concurrency_property():
    """concurrency property should reflect profile settings."""
    config = ScanConfig(speed_profile=SpeedProfile.AGGRESSIVE)
    assert config.concurrency == 20


def test_config_jitter_property():
    """jitter property should reflect profile settings."""
    config = ScanConfig(speed_profile=SpeedProfile.STEALTH)
    assert config.jitter == (1.0, 3.0)

    config_normal = ScanConfig(speed_profile=SpeedProfile.NORMAL)
    assert config_normal.jitter == (0.0, 0.0)


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def test_load_config_returns_defaults():
    """load_config() with no files or overrides returns defaults."""
    with patch("msscan.core.config._find_config_files", return_value=[]):
        config = load_config()
    assert config.rate_limit == 10
    assert config.speed_profile == SpeedProfile.NORMAL


def test_load_config_cli_overrides():
    """CLI overrides should take highest priority."""
    with patch("msscan.core.config._find_config_files", return_value=[]):
        config = load_config(cli_overrides={"rate_limit": 25, "timeout": 5.0})
    assert config.rate_limit == 25
    assert config.timeout == 5.0


def test_load_config_env_variables():
    """Environment variables should be applied."""
    env = {"MSSCAN_RATE_LIMIT": "30", "MSSCAN_TIMEOUT": "15.0"}
    with patch("msscan.core.config._find_config_files", return_value=[]):
        with patch.dict(os.environ, env, clear=False):
            config = load_config()
    assert config.rate_limit == 30
    assert config.timeout == 15.0


def test_load_config_toml_file(tmp_path):
    """Config loaded from a TOML file."""
    toml_content = """
[scan]
rate_limit = 5
timeout = 20.0
modules = ["xss", "sqli"]
"""
    config_file = tmp_path / "msscan.toml"
    config_file.write_text(toml_content, encoding="utf-8")

    with patch("msscan.core.config._find_config_files", return_value=[]):
        config = load_config(config_path=config_file)
    assert config.rate_limit == 5
    assert config.timeout == 20.0
    assert config.modules == ["xss", "sqli"]


# ---------------------------------------------------------------------------
# Config template
# ---------------------------------------------------------------------------

def test_generate_config_template():
    """Template should be valid TOML content."""
    template = generate_config_template()
    assert "[scan]" in template
    assert "[output]" in template
    assert "[profile.stealth]" in template
    assert "[profile.normal]" in template
    assert "[profile.aggressive]" in template
