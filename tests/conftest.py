"""Shared fixtures for nah tests."""

import os

import pytest

from nah import hook, paths
from nah.config import reset_config


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset project root, config cache, and sensitive paths between tests for isolation."""
    paths.reset_sensitive_paths()
    paths._sensitive_paths_merged = True  # prevent real config from polluting tests
    yield
    paths.reset_project_root()
    paths.reset_sensitive_paths()
    paths._sensitive_paths_merged = True
    reset_config()
    hook._transcript_path = ""


@pytest.fixture
def project_root(tmp_path):
    """Set project root to a temp dir. Use for context-dependent tests."""
    root = str(tmp_path / "project")
    os.makedirs(root, exist_ok=True)
    paths.set_project_root(root)
    return root
