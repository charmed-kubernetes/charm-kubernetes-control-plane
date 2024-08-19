import ops
from charms import kubernetes_snaps

SERVICES = {
    "api-server": "snap.kube-apiserver.daemon",
    "controller-manager": "snap.kube-controller-manager.daemon",
    "kube-scheduler": "snap.kube-scheduler.daemon",
}


def restart_action(event: ops.ActionEvent):
    """Handle the upgrade action."""
    try:
        for service, snap in SERVICES.items():
            kubernetes_snaps.service_restart(snap)
            event.set_results({service: {"status": "restarted"}})
    except Exception as e:
        event.fail(str(e))
