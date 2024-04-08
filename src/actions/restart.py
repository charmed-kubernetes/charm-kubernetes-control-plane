import charms.contextual_status as status
import ops
from charms import kubernetes_snaps


def restart_action(event: ops.ActionEvent):
    """Handle the upgrade action."""
    with status.context(event.framework.model.unit):
        kubernetes_snaps.service_restart("snap.kube-apiserver.daemon")
        event.set_results({"api-server": {"status": "restarted"}})
        kubernetes_snaps.service_restart("snap.kube-controller-manager.daemon")
        event.set_results({"controller-manager": {"status": "restarted"}})
        kubernetes_snaps.service_restart("snap.kube-scheduler.daemon")
        event.set_results({"kube-scheduler": {"status": "restarted"}})
