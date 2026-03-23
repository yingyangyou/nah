"""Unit tests for nah.paths — path resolution, sensitive checks, project root."""

import os
import sys
from unittest.mock import patch

import pytest

from nah import config, paths
from nah.config import NahConfig


# --- resolve_path ---


class TestResolvePath:
    def test_tilde_expansion(self):
        result = paths.resolve_path("~/file.txt")
        assert os.path.isabs(result)
        assert "~" not in result

    def test_env_var_expansion(self):
        home_var = "USERPROFILE" if sys.platform == "win32" else "HOME"
        result = paths.resolve_path(f"${home_var}/file.txt")
        assert result == os.path.realpath(os.path.join(os.path.expanduser("~"), "file.txt"))

    def test_relative_path(self):
        result = paths.resolve_path("./file.txt")
        assert os.path.isabs(result)

    def test_absolute_path(self):
        assert paths.resolve_path("/usr/bin/env") == os.path.realpath("/usr/bin/env")

    def test_empty(self):
        assert paths.resolve_path("") == ""


# --- friendly_path ---


class TestFriendlyPath:
    def test_home_prefix(self):
        home = os.path.expanduser("~")
        assert paths.friendly_path(home + os.sep + "file.txt") == "~" + os.sep + "file.txt"

    def test_home_exact(self):
        home = os.path.expanduser("~")
        assert paths.friendly_path(home) == "~"

    def test_non_home(self):
        assert paths.friendly_path("/usr/bin/env") == "/usr/bin/env"


# --- is_hook_path ---


class TestIsHookPath:
    def test_exact_hooks_dir(self):
        hooks = os.path.realpath(os.path.join(os.path.expanduser("~"), ".claude", "hooks"))
        assert paths.is_hook_path(hooks) is True

    def test_child_of_hooks(self):
        hooks = os.path.realpath(os.path.join(os.path.expanduser("~"), ".claude", "hooks"))
        assert paths.is_hook_path(hooks + os.sep + "nah_guard.py") is True

    def test_not_hooks(self):
        assert paths.is_hook_path("/tmp/something") is False

    def test_claude_but_not_hooks(self):
        claude = os.path.realpath(os.path.join(os.path.expanduser("~"), ".claude"))
        assert paths.is_hook_path(claude + os.sep + "settings.json") is False

    def test_empty(self):
        assert paths.is_hook_path("") is False


# --- is_sensitive ---


class TestIsSensitive:
    def test_ssh_block(self):
        resolved = paths.resolve_path("~/.ssh/id_rsa")
        matched, pattern, policy = paths.is_sensitive(resolved)
        assert matched is True
        assert pattern == "~/.ssh"
        assert policy == "block"

    def test_gnupg_block(self):
        resolved = paths.resolve_path("~/.gnupg/key")
        matched, _, policy = paths.is_sensitive(resolved)
        assert matched is True
        assert policy == "block"

    def test_git_credentials_block(self):
        resolved = paths.resolve_path("~/.git-credentials")
        matched, _, policy = paths.is_sensitive(resolved)
        assert matched is True
        assert policy == "block"

    def test_netrc_block(self):
        resolved = paths.resolve_path("~/.netrc")
        matched, _, policy = paths.is_sensitive(resolved)
        assert matched is True
        assert policy == "block"

    def test_aws_ask(self):
        resolved = paths.resolve_path("~/.aws/credentials")
        matched, _, policy = paths.is_sensitive(resolved)
        assert matched is True
        assert policy == "ask"

    def test_gcloud_ask(self):
        resolved = paths.resolve_path("~/.config/gcloud/credentials.json")
        matched, _, policy = paths.is_sensitive(resolved)
        assert matched is True
        assert policy == "ask"

    def test_azure_ask(self):
        resolved = paths.resolve_path("~/.azure/accessTokens.json")
        matched, pattern, policy = paths.is_sensitive(resolved)
        assert matched is True
        assert pattern == "~/.azure"
        assert policy == "ask"

    def test_github_cli_hosts_ask(self):
        resolved = paths.resolve_path("~/.config/gh/hosts.yml")
        matched, pattern, policy = paths.is_sensitive(resolved)
        assert matched is True
        assert pattern == "~/.config/gh"
        assert policy == "ask"

    def test_docker_config_ask(self):
        resolved = paths.resolve_path("~/.docker/config.json")
        matched, pattern, policy = paths.is_sensitive(resolved)
        assert matched is True
        assert pattern == "~/.docker/config.json"
        assert policy == "ask"

    def test_terraform_credentials_ask(self):
        resolved = paths.resolve_path("~/.terraform.d/credentials.tfrc.json")
        matched, pattern, policy = paths.is_sensitive(resolved)
        assert matched is True
        assert pattern == "~/.terraform.d/credentials.tfrc.json"
        assert policy == "ask"

    def test_terraformrc_ask(self):
        resolved = paths.resolve_path("~/.terraformrc")
        matched, pattern, policy = paths.is_sensitive(resolved)
        assert matched is True
        assert pattern == "~/.terraformrc"
        assert policy == "ask"

    def test_env_basename(self):
        matched, pattern, policy = paths.is_sensitive("/project/.env")
        assert matched is True
        assert pattern == ".env"
        assert policy == "ask"

    def test_env_local_now_matched(self):
        """FD-051: .env.local is now a default sensitive basename."""
        matched, pattern, policy = paths.is_sensitive("/project/.env.local")
        assert matched is True
        assert pattern == ".env.local"
        assert policy == "ask"

    def test_normal_path(self):
        matched, _, _ = paths.is_sensitive("/tmp/normal.txt")
        assert matched is False

    def test_empty(self):
        matched, _, _ = paths.is_sensitive("")
        assert matched is False


# --- check_path ---


class TestCheckPath:
    def setup_method(self):
        paths._sensitive_paths_merged = True  # isolate from live config

    def test_hook_block_for_write(self):
        result = paths.check_path("Write", "~/.claude/hooks/evil.py")
        assert result is not None
        assert result["decision"] == "block"
        assert "self-modification" in result["reason"]

    def test_hook_block_for_edit(self):
        result = paths.check_path("Edit", "~/.claude/hooks/nah_guard.py")
        assert result is not None
        assert result["decision"] == "block"

    def test_hook_ask_for_read(self):
        result = paths.check_path("Read", "~/.claude/hooks/nah_guard.py")
        assert result is not None
        assert result["decision"] == "ask"
        assert "hook directory" in result["reason"]

    def test_hook_ask_for_bash(self):
        result = paths.check_path("Bash", "~/.claude/hooks/")
        assert result is not None
        assert result["decision"] == "ask"

    def test_sensitive_block(self):
        result = paths.check_path("Read", "~/.ssh/id_rsa")
        assert result is not None
        assert result["decision"] == "block"
        assert "~/.ssh" in result["reason"]

    def test_sensitive_ask(self):
        result = paths.check_path("Read", "~/.aws/credentials")
        assert result is not None
        assert result["decision"] == "ask"

    def test_sensitive_ask_azure(self):
        result = paths.check_path("Read", "~/.azure/accessTokens.json")
        assert result is not None
        assert result["decision"] == "ask"
        assert "~/.azure" in result["reason"]

    def test_github_cli_hosts_ask(self):
        result = paths.check_path("Read", "~/.config/gh/hosts.yml")
        assert result is not None
        assert result["decision"] == "ask"
        assert "~/.config/gh" in result["reason"]

    def test_sensitive_ask_docker_config(self):
        result = paths.check_path("Read", "~/.docker/config.json")
        assert result is not None
        assert result["decision"] == "ask"
        assert "~/.docker/config.json" in result["reason"]

    def test_sensitive_ask_terraform_credentials(self):
        result = paths.check_path("Read", "~/.terraform.d/credentials.tfrc.json")
        assert result is not None
        assert result["decision"] == "ask"
        assert "~/.terraform.d/credentials.tfrc.json" in result["reason"]

    def test_sensitive_ask_terraformrc(self):
        result = paths.check_path("Read", "~/.terraformrc")
        assert result is not None
        assert result["decision"] == "ask"
        assert "~/.terraformrc" in result["reason"]

    def test_sensitive_block_home_env_var(self):
        home_var = "USERPROFILE" if sys.platform == "win32" else "HOME"
        result = paths.check_path("Read", f"${home_var}/.ssh/id_rsa")
        assert result is not None
        assert result["decision"] == "block"

    def test_sensitive_block_dynamic_user_substitution(self):
        result = paths.check_path("Read", "/Users/$(whoami)/.ssh/id_rsa")
        assert result is not None
        assert result["decision"] == "block"

    def test_sensitive_ask_home_glob(self):
        result = paths.check_path("Read", "/home/*/.aws/credentials")
        assert result is not None
        assert result["decision"] == "ask"

    def test_clean_path(self):
        result = paths.check_path("Read", "/tmp/safe.txt")
        assert result is None

    def test_empty_path(self):
        assert paths.check_path("Read", "") is None


# --- set/reset/get project root ---


class TestProjectRoot:
    def test_set_and_get(self):
        paths.set_project_root("/fake/project")
        assert paths.get_project_root() == "/fake/project"

    def test_reset_clears(self):
        paths.set_project_root("/fake/project")
        paths.reset_project_root()
        # After reset, get_project_root will auto-detect (via git).
        # We can't assert a specific value, but we can verify it doesn't
        # return the old value if we reset and set again.
        paths.set_project_root("/other/project")
        assert paths.get_project_root() == "/other/project"

    def test_autouse_fixture_resets(self):
        # This test runs after the autouse _reset_paths fixture,
        # so any previous set_project_root should be cleared.
        # We just verify set/get works from a clean state.
        paths.set_project_root("/test/root")
        assert paths.get_project_root() == "/test/root"


class TestTrustedPathNoGitRoot:
    """FD-107: trusted_paths should work even with no git root."""

    def teardown_method(self):
        config._cached_config = None

    def test_trusted_path_no_git_root(self):
        """Trusted path should allow even with no git root."""
        paths.set_project_root(None)
        config._cached_config = NahConfig(trusted_paths=["/tmp"])
        result = paths.check_project_boundary("Write", "/tmp/test.txt")
        assert result is None  # allowed

    def test_untrusted_path_no_git_root(self):
        """Untrusted path with no git root should still ask."""
        paths.set_project_root(None)
        config._cached_config = NahConfig()
        result = paths.check_project_boundary("Write", "/var/data/file.txt")
        assert result is not None
        assert result["decision"] == "ask"
        assert "no git root" in result["reason"]


# --- sensitive path config override ---


class TestSensitivePathConfigOverride:
    """FD-025: Verify config can override hardcoded sensitive path policies."""

    def _mock_config(self, sensitive_paths):
        return NahConfig(sensitive_paths=sensitive_paths)

    def test_override_ssh_block_to_ask(self):
        """Global config can relax ~/.ssh from block to ask."""
        with patch("nah.config.get_config", return_value=self._mock_config({"~/.ssh": "ask"})):
            paths.reset_sensitive_paths()
            result = paths.check_path("Read", "~/.ssh/id_rsa")
        assert result is not None
        assert result["decision"] == "ask"

    def test_unoverridden_path_keeps_default(self):
        """Paths not in config keep their hardcoded policy."""
        with patch("nah.config.get_config", return_value=self._mock_config({"~/.ssh": "ask"})):
            paths.reset_sensitive_paths()
            result = paths.check_path("Read", "~/.gnupg/key")
        assert result is not None
        assert result["decision"] == "block"

    def test_add_new_sensitive_path(self):
        """Config can add entirely new sensitive paths."""
        with patch("nah.config.get_config", return_value=self._mock_config({"~/.kube": "ask"})):
            paths.reset_sensitive_paths()
            result = paths.check_path("Read", "~/.kube/config")
        assert result is not None
        assert result["decision"] == "ask"

    def test_hook_path_immutable(self):
        """~/.claude/hooks stays blocked regardless of config."""
        with patch("nah.config.get_config", return_value=self._mock_config({})):
            paths.reset_sensitive_paths()
            result = paths.check_path("Edit", "~/.claude/hooks/nah_guard.py")
        assert result is not None
        assert result["decision"] == "block"
        assert "self-modification" in result["reason"]

    def test_merge_happens_once(self):
        """Merge is lazy and only runs once per lifecycle."""
        cfg = self._mock_config({"~/.ssh": "ask"})
        with patch("nah.config.get_config", return_value=cfg):
            paths.reset_sensitive_paths()
            paths._ensure_sensitive_paths_merged()
            assert paths._sensitive_paths_merged is True
            # Calling again should not re-merge (flag stays True)
            paths._ensure_sensitive_paths_merged()
            assert paths._sensitive_paths_merged is True

    def test_allow_removes_hardcoded_entry(self):
        """sensitive_paths: allow removes the path from sensitive list (nah-9lw)."""
        with patch("nah.config.get_config", return_value=self._mock_config({"~/.ssh": "allow"})):
            paths.reset_sensitive_paths()
            result = paths.check_path("Read", "~/.ssh/id_rsa")
        # Should not be flagged as sensitive (returns None or allow-level result)
        assert result is None or result.get("decision") != "block"

    def test_allow_only_removes_targeted_path(self):
        """sensitive_paths: allow on ~/.ssh should not affect ~/.gnupg."""
        with patch("nah.config.get_config", return_value=self._mock_config({"~/.ssh": "allow"})):
            paths.reset_sensitive_paths()
            result = paths.check_path("Read", "~/.gnupg/key")
        assert result is not None
        assert result["decision"] == "block"


# --- FD-051: Configurable sensitive basenames ---


class TestSensitiveBasenamesConfigurable:
    """FD-051: sensitive_basenames add/override/allow-remove, profile none."""

    def _mock_config(self, sensitive_basenames, profile="full"):
        return NahConfig(sensitive_basenames=sensitive_basenames, profile=profile)

    def test_new_defaults(self):
        """FD-051: new default sensitive basenames are present."""
        paths.reset_sensitive_paths()
        names = {e[0] for e in paths._SENSITIVE_BASENAMES}
        assert ".env" in names
        assert ".env.local" in names
        assert ".env.production" in names
        assert ".npmrc" in names
        assert ".pypirc" in names

    def test_add_new_basename(self):
        """Config adds a new sensitive basename."""
        with patch("nah.config.get_config", return_value=self._mock_config({".secrets": "block"})):
            paths.reset_sensitive_paths()
            matched, pattern, policy = paths.is_sensitive("/project/.secrets")
        assert matched is True
        assert policy == "block"

    def test_override_existing_basename(self):
        """Config overrides .env from ask to block."""
        with patch("nah.config.get_config", return_value=self._mock_config({".env": "block"})):
            paths.reset_sensitive_paths()
            matched, _, policy = paths.is_sensitive("/project/.env")
        assert matched is True
        assert policy == "block"

    def test_allow_removes_basename(self):
        """allow policy removes a basename from defaults."""
        with patch("nah.config.get_config", return_value=self._mock_config({".env": "allow"})):
            paths.reset_sensitive_paths()
            matched, _, _ = paths.is_sensitive("/project/.env")
        assert matched is False

    def test_allow_removes_only_targeted(self):
        """allow on .env doesn't affect .env.local."""
        with patch("nah.config.get_config", return_value=self._mock_config({".env": "allow"})):
            paths.reset_sensitive_paths()
            matched, _, _ = paths.is_sensitive("/project/.env.local")
        assert matched is True

    def test_profile_none_clears_basenames(self):
        """profile: none clears all basenames."""
        with patch("nah.config.get_config", return_value=self._mock_config({}, profile="none")):
            paths.reset_sensitive_paths()
            matched, _, _ = paths.is_sensitive("/project/.env")
        assert matched is False

    def test_profile_none_with_config(self):
        """profile: none clears defaults, but config entries still apply."""
        with patch("nah.config.get_config", return_value=self._mock_config({".secrets": "block"}, profile="none")):
            paths.reset_sensitive_paths()
            matched_env, _, _ = paths.is_sensitive("/project/.env")
            matched_secrets, _, policy = paths.is_sensitive("/project/.secrets")
        assert matched_env is False  # cleared by none
        assert matched_secrets is True
        assert policy == "block"

    def test_reset_restores_basenames(self):
        """reset_sensitive_paths restores basenames to defaults."""
        paths._SENSITIVE_BASENAMES.clear()
        paths.reset_sensitive_paths()
        names = {e[0] for e in paths._SENSITIVE_BASENAMES}
        assert ".env" in names
        assert ".env.local" in names


# --- FD-075: Config self-protection ---


class TestIsNahConfigPath:
    """FD-075: is_nah_config_path() detects nah config paths."""

    def test_exact_config_dir(self):
        assert paths.is_nah_config_path(paths._NAH_CONFIG_DIR) is True

    def test_child_of_config_dir(self):
        resolved = os.path.realpath(os.path.join(paths._NAH_CONFIG_DIR, "config.yaml"))
        assert paths.is_nah_config_path(resolved) is True

    def test_not_config_dir(self):
        assert paths.is_nah_config_path("/tmp/something") is False

    def test_config_sibling_not_matched(self):
        """Sibling of config dir is not nah config."""
        resolved = os.path.realpath(os.path.join(os.path.dirname(paths._NAH_CONFIG_DIR), "other"))
        assert paths.is_nah_config_path(resolved) is False

    def test_prefix_collision(self):
        """nah-evil should not match (prefix without separator)."""
        resolved = os.path.realpath(os.path.join(os.path.dirname(paths._NAH_CONFIG_DIR), "nah-evil"))
        assert paths.is_nah_config_path(resolved) is False

    def test_empty(self):
        assert paths.is_nah_config_path("") is False


class TestConfigSelfProtection:
    """FD-075: check_path and check_path_basic protect nah config dir."""

    def setup_method(self):
        paths._sensitive_paths_merged = True

    @property
    def _config_yaml(self):
        return os.path.join(paths._NAH_CONFIG_DIR, "config.yaml")

    def test_check_path_basic_returns_ask(self):
        resolved = os.path.realpath(self._config_yaml)
        result = paths.check_path_basic(resolved)
        assert result is not None
        decision, reason = result
        assert decision == "ask"
        assert "nah config" in reason

    def test_check_path_write_ask(self):
        result = paths.check_path("Write", self._config_yaml)
        assert result is not None
        assert result["decision"] == "ask"
        assert "nah config" in result["reason"]
        assert "guard self-protection" in result["reason"]

    def test_check_path_edit_ask(self):
        result = paths.check_path("Edit", self._config_yaml)
        assert result is not None
        assert result["decision"] == "ask"
        assert "nah config" in result["reason"]

    def test_check_path_read_ask(self):
        result = paths.check_path("Read", self._config_yaml)
        assert result is not None
        assert result["decision"] == "ask"
        assert "nah config" in result["reason"]

    def test_not_block_like_hook(self):
        """Config path gets ASK for Write/Edit, NOT BLOCK (unlike hook path)."""
        write_result = paths.check_path("Write", self._config_yaml)
        hook_result = paths.check_path("Write", "~/.claude/hooks/nah_guard.py")
        assert write_result["decision"] == "ask"
        assert hook_result["decision"] == "block"

    def test_survives_profile_none(self):
        """Config path protection is hardcoded — not cleared by profile: none."""
        # Simulate profile: none clearing _SENSITIVE_DIRS
        paths._SENSITIVE_DIRS.clear()
        paths._SENSITIVE_BASENAMES.clear()

        # Config path should STILL be caught (hardcoded, not in _SENSITIVE_DIRS)
        result = paths.check_path("Write", self._config_yaml)
        assert result is not None
        assert result["decision"] == "ask"
        assert "nah config" in result["reason"]

        # Contrast: a regular sensitive path is gone
        result_ssh = paths.check_path("Read", "~/.ssh/id_rsa")
        # Only check_path_basic would catch it, but _SENSITIVE_DIRS is cleared
        # Hook check doesn't match, nah config check doesn't match, is_sensitive returns False
        assert result_ssh is None

    def test_subdirectory_protected(self):
        """Subdirectories of nah config dir are also protected."""
        subpath = os.path.join(paths._NAH_CONFIG_DIR, "subdir", "file.txt")
        result = paths.check_path("Write", subpath)
        assert result is not None
        assert result["decision"] == "ask"

    def test_nah_log_protected(self):
        """Log file in config dir is protected."""
        logpath = os.path.join(paths._NAH_CONFIG_DIR, "nah.log")
        result = paths.check_path("Write", logpath)
        assert result is not None
        assert result["decision"] == "ask"


class TestSettingsJsonProtection:
    """FD-075: ~/.claude/settings.json in _SENSITIVE_DIRS."""

    def test_settings_json_in_defaults(self):
        """settings.json is in the default sensitive dirs."""
        resolved = paths.resolve_path("~/.claude/settings.json")
        matched, pattern, policy = paths.is_sensitive(resolved)
        assert matched is True
        assert policy == "ask"
        assert "settings.json" in pattern

    def test_settings_local_json_in_defaults(self):
        """settings.local.json is in the default sensitive dirs."""
        resolved = paths.resolve_path("~/.claude/settings.local.json")
        matched, pattern, policy = paths.is_sensitive(resolved)
        assert matched is True
        assert policy == "ask"
        assert "settings.local.json" in pattern

    def test_check_path_catches_settings(self):
        result = paths.check_path("Write", "~/.claude/settings.json")
        assert result is not None
        assert result["decision"] == "ask"
        assert "sensitive path" in result["reason"]

    def test_settings_cleared_by_profile_none(self):
        """settings.json protection IS cleared by profile: none (by design)."""
        paths._SENSITIVE_DIRS.clear()
        resolved = paths.resolve_path("~/.claude/settings.json")
        matched, _, _ = paths.is_sensitive(resolved)
        assert matched is False


# --- Windows compatibility ---


class TestSplitPathParts:
    """_split_path_parts handles both / and \\ separators."""

    def test_unix_forward_slashes(self):
        result = paths._split_path_parts("/home/user/.ssh/id_rsa")
        assert result == ["home", "user", ".ssh", "id_rsa"]

    def test_windows_backslashes(self):
        result = paths._split_path_parts(r"C:\Users\test\.ssh\id_rsa")
        assert result == ["C:", "Users", "test", ".ssh", "id_rsa"]

    def test_mixed_separators(self):
        result = paths._split_path_parts("C:\\Users/test/.ssh\\id_rsa")
        assert result == ["C:", "Users", "test", ".ssh", "id_rsa"]

    def test_dot_stripped(self):
        result = paths._split_path_parts("./relative/path")
        assert result == ["relative", "path"]

    def test_empty(self):
        assert paths._split_path_parts("") == []


class TestWindowsConfigDir:
    """_NAH_CONFIG_DIR is platform-appropriate."""

    def test_config_dir_is_absolute(self):
        assert os.path.isabs(paths._NAH_CONFIG_DIR)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_windows_config_dir_uses_appdata(self):
        appdata = os.environ.get("APPDATA", "")
        assert appdata, "APPDATA must be set on Windows"
        assert paths._NAH_CONFIG_DIR.startswith(appdata)

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix only")
    def test_unix_config_dir_uses_dot_config(self):
        home = os.path.expanduser("~")
        assert paths._NAH_CONFIG_DIR.startswith(os.path.realpath(os.path.join(home, ".config")))


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
class TestWindowsSensitivePaths:
    """Windows-specific sensitive path entries."""

    def test_appdata_gcloud_sensitive(self):
        appdata = os.environ.get("APPDATA", "")
        if not appdata:
            pytest.skip("APPDATA not set")
        resolved = os.path.realpath(os.path.join(appdata, "gcloud", "credentials.json"))
        matched, _, policy = paths.is_sensitive(resolved)
        assert matched is True
        assert policy == "ask"

    def test_appdata_github_cli_sensitive(self):
        appdata = os.environ.get("APPDATA", "")
        if not appdata:
            pytest.skip("APPDATA not set")
        resolved = os.path.realpath(os.path.join(appdata, "GitHub CLI", "state.json"))
        matched, _, policy = paths.is_sensitive(resolved)
        assert matched is True
        assert policy == "ask"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
class TestMsys2PathConversion:
    """MSYS2/Git Bash drive paths (/d/..., /c/...) convert to Windows paths."""

    def test_drive_letter_d(self):
        result = paths.resolve_path("/d/Projects/foo")
        assert result.startswith("D:\\")
        assert "Projects" in result
        assert "\\d\\" not in result

    def test_drive_letter_c(self):
        result = paths.resolve_path("/c/Windows/System32")
        assert result.startswith("C:\\")
        assert "\\c\\" not in result

    def test_uppercase_preserved(self):
        result = paths.resolve_path("/D/Projects/foo")
        assert result.startswith("D:\\")

    def test_bare_drive_letter(self):
        """Just /d resolves to D:\\ root."""
        result = paths.resolve_path("/d")
        assert result.upper().startswith("D:\\")

    def test_non_drive_path_unchanged(self):
        """Regular absolute paths are not affected."""
        result = paths.resolve_path("/usr/bin/env")
        # On Windows this resolves relative to current drive
        assert "\\usr\\" in result

    def test_two_char_start_not_drive(self):
        """Paths like /dd/foo are NOT drive letters (dd is two chars)."""
        result = paths.resolve_path("/dd/foo")
        assert "\\dd\\" in result
