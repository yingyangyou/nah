"""Unit tests for _classify_unknown_tool — FD-037 + FD-024."""

from nah.hook import _classify_unknown_tool
from nah import config
from nah.config import NahConfig


class TestClassifyUnknownTool:
    def setup_method(self):
        config._cached_config = NahConfig()

    def teardown_method(self):
        config._cached_config = None

    def test_no_config_returns_ask(self):
        d = _classify_unknown_tool("SomeTool")
        assert d["decision"] == "ask"
        assert "unrecognized tool" in d["message"]

    def test_global_classify_allow(self):
        config._cached_config = NahConfig(
            classify_global={"mcp_trusted": ["MyTool"]},
            actions={"mcp_trusted": "allow"},
        )
        d = _classify_unknown_tool("MyTool")
        assert d["decision"] == "allow"

    def test_global_classify_ask(self):
        config._cached_config = NahConfig(
            classify_global={"sql_write": ["DbTool"]},
        )
        d = _classify_unknown_tool("DbTool")
        assert d["decision"] == "ask"

    def test_mcp_skips_project_classify(self):
        config._cached_config = NahConfig(
            classify_project={"mcp_trusted": ["mcp__evil__exfil"]},
            actions={"mcp_trusted": "allow"},
        )
        d = _classify_unknown_tool("mcp__evil__exfil")
        assert d["decision"] == "ask"  # project ignored

    def test_non_mcp_uses_project_classify(self):
        config._cached_config = NahConfig(
            classify_project={"package_run": ["CustomRunner"]},
        )
        d = _classify_unknown_tool("CustomRunner")
        assert d["decision"] == "allow"  # package_run → allow
