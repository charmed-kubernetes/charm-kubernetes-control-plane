from unittest.mock import MagicMock, call, patch

import ops
import pytest
from charms import kubernetes_snaps
from ops.testing import Harness

import service_restarts
from service_restarts import ServiceRestarts


class _Charm(ops.CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.service_restarts = ServiceRestarts(self)


@pytest.fixture
def restarts():
    harness = Harness(_Charm, meta="name: test")
    harness.begin()
    yield harness.charm.service_restarts
    harness.cleanup()


@pytest.fixture
def lib_restart():
    with patch("charms.kubernetes_snaps.service_restart") as mock:
        yield mock


def _configure(restarts, service="kube-apiserver", extra_files=()):
    with restarts.restart_on_change(service, extra_files=extra_files):
        # what configure_kubernetes_service does after `snap set`
        kubernetes_snaps.service_restart(f"snap.{service}.daemon")


@patch("service_restarts.is_active", MagicMock(return_value=True))
@patch("service_restarts.fingerprint")
def test_restart_only_on_change(fingerprint, restarts, lib_restart):
    fingerprint.return_value = "a"
    _configure(restarts)
    _configure(restarts)
    lib_restart.assert_called_once_with("snap.kube-apiserver.daemon")

    fingerprint.return_value = "b"
    _configure(restarts)
    assert lib_restart.call_count == 2


@patch("service_restarts.is_active", MagicMock(return_value=False))
@patch("service_restarts.fingerprint", MagicMock(return_value="a"))
def test_restart_when_inactive(restarts, lib_restart):
    _configure(restarts)
    _configure(restarts)
    assert lib_restart.call_args_list == [call("snap.kube-apiserver.daemon")] * 2


@patch("service_restarts.fingerprint", MagicMock(return_value="a"))
def test_library_restart_restored_on_error(restarts, lib_restart):
    with pytest.raises(RuntimeError):
        with restarts.restart_on_change("kube-apiserver"):
            raise RuntimeError()
    assert kubernetes_snaps.service_restart is lib_restart
    lib_restart.assert_not_called()


def test_fingerprint_tracks_referenced_files(tmp_path):
    kubeconfig, extra = tmp_path / "kubeconfig", tmp_path / "ca.crt"
    kubeconfig.write_text("one")
    extra.write_text("ca")
    args = f'--kubeconfig="{kubeconfig}" --v="2"'
    with patch("service_restarts._snap_args", return_value=args):
        first = service_restarts.fingerprint("kubelet", [str(extra)])
        assert first == service_restarts.fingerprint("kubelet", [str(extra)])
        kubeconfig.write_text("two")
        second = service_restarts.fingerprint("kubelet", [str(extra)])
        assert second != first
        extra.write_text("new-ca")
        assert service_restarts.fingerprint("kubelet", [str(extra)]) != second
    with patch("service_restarts._snap_args", return_value=args.replace("2", "3")):
        assert service_restarts.fingerprint("kubelet", [str(extra)]) != second


@patch("charms.kubernetes_snaps.configure_services_restart_always")
def test_ensure_restart_always(configure, restarts):
    with patch("service_restarts._read_text", return_value=service_restarts.RESTART_ALWAYS_CONF):
        restarts.ensure_restart_always(control_plane=True)
    configure.assert_not_called()
    with patch("service_restarts._read_text", return_value=""):
        restarts.ensure_restart_always(control_plane=True)
    configure.assert_called_once_with(control_plane=True)


def _systemctl_show(n_restarts, state="active", result="success", exit_status="0"):
    return (
        f"ActiveState={state}\nResult={result}\n"
        f"ExecMainStatus={exit_status}\nNRestarts={n_restarts}\n"
    ).encode()


@patch("subprocess.run")
@patch("subprocess.check_output")
def test_service_has_failed_tracks_restart_growth(check_output, run, restarts):
    service = "snap.kube-apiserver.daemon.service"
    # A high lifetime count alone is not a failure
    check_output.return_value = _systemctl_show(50)
    assert restarts.service_has_failed(service) == (False, "")
    check_output.return_value = _systemctl_show(52)
    assert restarts.service_has_failed(service) == (False, "")
    # Crash-looping between checks is reported
    check_output.return_value = _systemctl_show(60)
    assert restarts.service_has_failed(service) == (
        True,
        f"{service} is restarting repeatedly",
    )
    # The health check never restarts services itself
    run.assert_not_called()


@patch("subprocess.check_output")
def test_service_has_failed_states(check_output, restarts):
    check_output.return_value = _systemctl_show(0, state="failed", result="exit-code")
    failed, reason = restarts.service_has_failed("kubelet")
    assert failed and "ActiveState=failed" in reason
    check_output.return_value = _systemctl_show(0, exit_status="1")
    failed, reason = restarts.service_has_failed("kubelet")
    assert failed and "ExecMainStatus=1" in reason
