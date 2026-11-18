"""The auth-webhook restarts only when something it loads changed."""

import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import charms.contextual_status as status
import pytest
from ops import BlockedStatus

import auth_webhook

UNIT = auth_webhook.auth_webhook_svc_name
REPO_ROOT = Path(__file__).parents[2]


def show(state="active", reload="no", started_ago=100.0):
    """`systemctl show` output for a unit started `started_ago` seconds ago."""
    monotonic_us = int((time.monotonic() - started_ago) * 1e6)
    start = time.time() - time.monotonic() + monotonic_us / 1e6
    calendar = datetime.fromtimestamp(start, timezone.utc).strftime("%a %Y-%m-%d %H:%M:%S.%f UTC")
    out = (
        f"ActiveState={state}\nNeedDaemonReload={reload}\n"
        f"ExecMainStartTimestampMonotonic={monotonic_us}\nExecMainStartTimestamp={calendar}\n"
    )
    return out.encode(), start


def redirect_paths(tmp_path, monkeypatch):
    """Point every path the module writes into tmp_path."""
    root = tmp_path / "auth-webhook"
    paths = {
        "auth_webhook_root": str(root),
        "auth_webhook_conf": str(root / "auth-webhook-conf.yaml"),
        "authz_webhook_conf": root / "authz-webhook-conf.yaml",
        "auth_webhook_exe": str(root / "auth-webhook.py"),
        # wokeignore:rule=master
        "auth_webhook_svc": str(tmp_path / "cdk.master.auth-webhook.service"),
        "auth_webhook_logrotate": str(tmp_path / "auth-webhook.logrotate"),
        "log_dir": str(tmp_path / "log"),
        "auth_webhook_certs": (str(tmp_path / "server.crt"), str(tmp_path / "server.key")),
    }
    for name, value in paths.items():
        monkeypatch.setattr(auth_webhook, name, value)
    for cert in paths["auth_webhook_certs"]:
        Path(cert).write_text("cert")
    return paths


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Fake systemd and a redirected filesystem for `auth_webhook.configure`."""
    paths = redirect_paths(tmp_path, monkeypatch)
    sd = SimpleNamespace(show=show(state="inactive")[0], calls=[], restart_fails=False, cores=2)

    def check_output(cmd, *args, **kwargs):
        if cmd[0] == "systemctl":
            return sd.show
        if cmd[0] == "nproc":
            return str(sd.cores).encode()
        raise AssertionError(f"unexpected command {cmd}")

    def check_call(cmd, *args, **kwargs):
        sd.calls.append(list(cmd))
        if cmd[:2] == ["systemctl", "restart"] and sd.restart_fails:
            raise subprocess.CalledProcessError(1, cmd)

    for module in (auth_webhook, auth_webhook.kubernetes_snaps):
        monkeypatch.setattr(module, "check_output", check_output)
        monkeypatch.setattr(module, "check_call", check_call)
    monkeypatch.setattr(auth_webhook, "_uplift_keystone_endpoint", lambda: "")
    monkeypatch.setattr(auth_webhook, "_uplift_aws_iam_endpoint", lambda: "")
    monkeypatch.chdir(REPO_ROOT)  # templates are loaded relative to the charm root

    sd.paths = paths
    sd.written = [
        paths["auth_webhook_conf"],
        paths["auth_webhook_exe"],
        paths["auth_webhook_logrotate"],
        paths["auth_webhook_svc"],
        str(paths["authz_webhook_conf"]),
    ]

    def configure(**kwargs):
        kwargs.setdefault("custom_authz_config_file", "authz: config\n")
        unit = mock.MagicMock()
        with status.context(unit):
            auth_webhook.configure("/charm", **kwargs)
        return unit

    def settle(started_ago=100.0):
        """Mark the service running, with every file older than its start."""
        sd.show, start = show(started_ago=started_ago)
        for path in sd.written + list(paths["auth_webhook_certs"]):
            os.utime(path, (start - 50, start - 50))
        sd.calls.clear()
        return start

    sd.configure, sd.settle = configure, settle
    return sd


def restarted(env):
    return ["systemctl", "restart", UNIT] in env.calls


def stat_of(paths):
    return {p: (os.stat(p).st_ino, os.stat(p).st_mtime) for p in paths}


def test_first_configure_writes_every_file_and_starts_the_service(env):
    env.configure()

    for path in env.written:
        assert os.path.exists(path), path
    assert ["systemctl", "daemon-reload"] in env.calls  # the unit file is new
    assert restarted(env)  # the service is inactive


def test_unchanged_configure_rewrites_nothing_and_restarts_nothing(env, caplog):
    caplog.set_level("INFO")
    env.configure()
    env.settle()
    before = stat_of(env.written)

    env.configure()

    assert stat_of(env.written) == before
    assert env.calls == []
    assert f"{UNIT}: no change" in caplog.messages


@pytest.mark.parametrize(
    "change",
    [
        pytest.param({"custom_authn_endpoint": "https://authn.example.com"}, id="auth-webhook.py"),
        pytest.param({"cores": 4}, id="unit file"),
    ],
)
def test_changed_rendered_input_restarts(env, change):
    env.configure()
    env.settle()

    env.cores = change.pop("cores", env.cores)
    env.configure(**change)

    assert restarted(env)


@pytest.mark.parametrize("cert", [0, 1], ids=["server.crt", "server.key"])
def test_newer_certificate_or_key_restarts(env, cert):
    env.configure()
    start = env.settle()
    path = env.paths["auth_webhook_certs"][cert]
    os.utime(path, (start + 1, start + 1))

    env.configure()

    assert restarted(env)


def test_changed_unit_file_reloads_systemd_before_restarting(env):
    env.configure()
    env.settle()
    env.cores = 4

    env.configure()

    assert env.calls.index(["systemctl", "daemon-reload"]) < env.calls.index(
        ["systemctl", "restart", UNIT]
    )


def test_files_the_process_does_not_load_do_not_restart_it(env):
    env.configure()
    start = env.settle()
    # The API server's webhook config and the authz config are not inputs of the service.
    for path in (env.paths["auth_webhook_conf"], str(env.paths["authz_webhook_conf"])):
        os.utime(path, (start + 1, start + 1))

    env.configure()

    assert env.calls == []


def test_changed_authz_config_is_written_without_restarting(env):
    env.configure()
    env.settle()

    env.configure(custom_authz_config_file="authz: new\n")

    assert env.paths["authz_webhook_conf"].read_text() == "authz: new\n"
    assert env.calls == []


def test_inactive_service_restarts_even_when_nothing_changed(env):
    env.configure()
    env.settle()
    env.show, _ = show(state="inactive")

    env.configure()

    assert restarted(env)


def test_pending_daemon_reload_is_applied(env):
    env.configure()
    env.settle()
    env.show, _ = show(reload="yes")

    env.configure()

    assert ["systemctl", "daemon-reload"] in env.calls
    assert restarted(env)


def test_failed_restart_shows_blocked_and_the_next_hook_retries(env):
    env.restart_fails = True
    unit = mock.MagicMock()
    with status.context(unit):
        with pytest.raises(status.ReconcilerError):
            auth_webhook.configure("/charm")
    assert unit.status == BlockedStatus("Failed to restart Kubernetes services")

    env.restart_fails = False
    env.calls.clear()
    env.configure()
    assert restarted(env)  # still inactive, so the service restarts on the next hook
