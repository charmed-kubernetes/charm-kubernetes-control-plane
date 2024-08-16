from unittest import mock

import charms.contextual_status as status
import ops
import pytest

import actions.restart
import actions.upgrade
from charm import KubernetesControlPlaneCharm


@pytest.fixture
def harness():
    harness = ops.testing.Harness(KubernetesControlPlaneCharm)
    try:
        harness.begin_with_initial_hooks()
        yield harness
    finally:
        harness.cleanup()


@mock.patch.object(actions.upgrade.kubernetes_snaps, "upgrade_snaps")
def test_upgrade_action_success(upgrade_snaps: mock.Mock, harness):
    """Verify that the upgrade action runs the upgrade_snap method and reconciles."""

    def mock_reconciler(_):
        status.add(ops.BlockedStatus("reconciled"))

    harness.model.unit.status = ops.model.BlockedStatus("pre-test")
    with mock.patch.object(
        harness.charm.reconciler, "reconcile_function", side_effect=mock_reconciler
    ) as mocked_reconciler:
        harness.run_action("upgrade")
    upgrade_snaps.assert_called_once()
    mocked_reconciler.assert_called_once()
    assert harness.model.unit.status == ops.BlockedStatus("reconciled")


@mock.patch.object(actions.upgrade.kubernetes_snaps, "upgrade_snaps")
def test_upgrade_action_fails(upgrade_snaps: mock.Mock, harness):
    """Verify that the upgrade action runs the upgrade_snap method and reconciles."""

    def mock_upgrade(channel, event, control_plane):
        assert channel == "latest/edge"
        assert control_plane is True
        status.add(ops.BlockedStatus("snap-upgrade-failed"))
        event.fail("snap upgrade failed")

    upgrade_snaps.side_effect = mock_upgrade

    harness.model.unit.status = ops.model.BlockedStatus("pre-test")
    with mock.patch.object(harness.charm.reconciler, "reconcile_function") as mocked_reconciler:
        with pytest.raises(ops.testing.ActionFailed) as action_err:
            harness.run_action("upgrade")
    upgrade_snaps.assert_called_once()
    mocked_reconciler.assert_not_called()
    assert action_err.value.message == "snap upgrade failed"
    assert harness.model.unit.status == ops.BlockedStatus("snap-upgrade-failed")


@mock.patch.object(actions.restart.kubernetes_snaps, "service_restart")
def test_restart_action_success(service_restart: mock.Mock, harness):
    """Verify that the restart action runs the service_restart method."""
    harness.run_action("restart")
    service_restart.assert_has_calls(
        [
            mock.call("snap.kube-apiserver.daemon"),
            mock.call("snap.kube-controller-manager.daemon"),
            mock.call("snap.kube-scheduler.daemon"),
        ]
    )


@mock.patch.object(
    actions.restart.kubernetes_snaps,
    "service_restart",
    side_effect=Exception("snap restart failed"),
)
def test_restart_action_fails(service_restart: mock.Mock, harness):
    """Verify that the restart action fails the service_restart method."""
    with pytest.raises(ops.testing.ActionFailed) as action_err:
        harness.run_action("restart")

    service_restart.assert_called_once_with("snap.kube-apiserver.daemon")
    assert action_err.value.message == "snap restart failed"
