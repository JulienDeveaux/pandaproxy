"""Tests for the CLI's Docker-secrets (_FILE) environment variable resolution."""

import importlib
import os

import pytest

import pandaproxy.cli
from pandaproxy.cli import resolve_file_env_var


def test_resolve_file_env_var_reads_file_when_var_unset(monkeypatch, tmp_path):
    secret_file = tmp_path / "access_code"
    secret_file.write_text("supersecret\n")
    monkeypatch.delenv("ACCESS_CODE", raising=False)
    monkeypatch.setenv("ACCESS_CODE_FILE", str(secret_file))

    resolve_file_env_var("ACCESS_CODE")

    assert os.environ["ACCESS_CODE"] == "supersecret"


def test_resolve_file_env_var_prefers_existing_var(monkeypatch, tmp_path):
    secret_file = tmp_path / "access_code"
    secret_file.write_text("from-file")
    monkeypatch.setenv("ACCESS_CODE", "from-env")
    monkeypatch.setenv("ACCESS_CODE_FILE", str(secret_file))

    resolve_file_env_var("ACCESS_CODE")

    assert os.environ["ACCESS_CODE"] == "from-env"


def test_resolve_file_env_var_noop_when_neither_set(monkeypatch):
    monkeypatch.delenv("ACCESS_CODE", raising=False)
    monkeypatch.delenv("ACCESS_CODE_FILE", raising=False)

    resolve_file_env_var("ACCESS_CODE")

    assert "ACCESS_CODE" not in os.environ


def test_resolve_file_env_var_raises_clear_error_when_file_missing(
    monkeypatch, tmp_path
):
    monkeypatch.delenv("ACCESS_CODE", raising=False)
    monkeypatch.setenv("ACCESS_CODE_FILE", str(tmp_path / "does-not-exist"))

    with pytest.raises(
        RuntimeError, match="ACCESS_CODE_FILE points to a nonexistent file"
    ):
        resolve_file_env_var("ACCESS_CODE")

    assert "ACCESS_CODE" not in os.environ


def test_resolve_file_env_var_raises_clear_error_when_path_unreadable(
    monkeypatch, tmp_path
):
    # A directory triggers the same OSError branch as a permission-denied file,
    # without depending on the test runner not being root (CI runs as root).
    monkeypatch.delenv("ACCESS_CODE", raising=False)
    monkeypatch.setenv("ACCESS_CODE_FILE", str(tmp_path))

    with pytest.raises(RuntimeError, match="Failed to read ACCESS_CODE_FILE"):
        resolve_file_env_var("ACCESS_CODE")

    assert "ACCESS_CODE" not in os.environ


def test_module_import_resolves_access_code_file(monkeypatch, tmp_path):
    # cli.py calls resolve_file_env_var("ACCESS_CODE") at module level (on
    # import), not just as a function tests can call directly. Reloading is
    # the only way to actually exercise that top-level statement.
    secret_file = tmp_path / "access_code"
    secret_file.write_text("supersecret\n")
    monkeypatch.delenv("ACCESS_CODE", raising=False)
    monkeypatch.setenv("ACCESS_CODE_FILE", str(secret_file))

    try:
        importlib.reload(pandaproxy.cli)
        assert os.environ["ACCESS_CODE"] == "supersecret"
    finally:
        # resolve_file_env_var writes os.environ directly, bypassing
        # monkeypatch's tracking, so it won't be auto-reverted - clean up
        # and restore the module to its normal (non-reloaded) state.
        monkeypatch.delenv("ACCESS_CODE", raising=False)
        importlib.reload(pandaproxy.cli)


def test_module_import_raises_clear_error_when_access_code_file_missing(
    monkeypatch, tmp_path
):
    monkeypatch.delenv("ACCESS_CODE", raising=False)
    monkeypatch.setenv("ACCESS_CODE_FILE", str(tmp_path / "does-not-exist"))

    try:
        with pytest.raises(
            RuntimeError, match="ACCESS_CODE_FILE points to a nonexistent file"
        ):
            importlib.reload(pandaproxy.cli)
    finally:
        monkeypatch.delenv("ACCESS_CODE_FILE", raising=False)
        importlib.reload(pandaproxy.cli)
