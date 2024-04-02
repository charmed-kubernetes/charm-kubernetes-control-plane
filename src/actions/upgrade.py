import charms.contextual_status as status
import ops
from charms import kubernetes_snaps


def upgrade_action(event: ops.ActionEvent):
    """Handle the upgrade action."""
    with status.context(event.framework.model.unit):
        channel = event.framework.model.config.get("channel")
        kubernetes_snaps.upgrade_snaps(channel=channel, event=event, control_plane=True)
