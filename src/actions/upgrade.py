import ops
from charms import kubernetes_snaps


def upgrade_action(charm, event: ops.ActionEvent):
    """Handle the upgrade action."""
    channel = event.framework.model.config.get("channel")
    try:
        kubernetes_snaps.upgrade_snaps(channel=channel, event=event, control_plane=True)
    except Exception as e:
        event.fail(str(e))
        return

    # Post successful upgrade, reconcile the charm to ensure it is in the desired state
    charm.reconciler.reconcile(event)
