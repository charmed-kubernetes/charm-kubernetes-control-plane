"""Restart Kubernetes snap services only when their effective configuration changes.

The kubernetes_snaps library restarts a service every time it is configured,
and the reconciler configures every service on every hook. This module
suppresses those unconditional restarts and restarts a service only when its
snap args, or a file those args point at, has changed since the last restart.
"""

import hashlib
import logging
import shlex
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Tuple

import charms.contextual_status as status
import ops
from charms import kubernetes_snaps

log = logging.getLogger(__name__)

# Must match the drop-in written by kubernetes_snaps.configure_services_restart_always
RESTART_ALWAYS_CONF = """[Unit]
StartLimitIntervalSec=0

[Service]
RestartSec=10"""

# A service restarting more often than this between two health checks is crash-looping
MAX_RESTARTS_BETWEEN_CHECKS = 3


def _hash_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        return ""


def _read_text(path: Path) -> str:
    try:
        return path.read_text()
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        return ""


def _snap_args(service: str) -> str:
    try:
        return subprocess.check_output(["snap", "get", service, "args"]).decode("utf-8")
    except subprocess.CalledProcessError:
        return ""


def fingerprint(service: str, extra_files: Iterable[str] = ()) -> str:
    """Digest of a service's snap args and every file those args reference."""
    args = _snap_args(service)
    digest = hashlib.sha256(args.encode("utf-8"))
    files = []
    for token in shlex.split(args):
        value = token.split("=", 1)[-1]
        if value.startswith("/") and Path(value).is_file():
            files.append(value)
    for path in sorted(set(files) | set(map(str, extra_files))):
        digest.update(f"{path}={_hash_file(Path(path))}".encode("utf-8"))
    return digest.hexdigest()


def is_active(unit: str) -> bool:
    """Whether a systemd unit is running."""
    return subprocess.call(["systemctl", "is-active", "--quiet", unit]) == 0


class ServiceRestarts(ops.Object):
    """Track service configuration and restart services only when it changes."""

    stored = ops.StoredState()

    def __init__(self, charm: ops.CharmBase):
        super().__init__(charm, "service-restarts")
        self.stored.set_default(fingerprints={}, restart_counts={})

    @contextmanager
    def restart_on_change(self, service: str, extra_files: Iterable[str] = ()):
        """Suppress library restarts in the block, then restart if the config changed.

        Args:
            service: snap name of the service, e.g. "kube-apiserver"
            extra_files: files the service reads that aren't referenced by its args

        """
        restart = kubernetes_snaps.service_restart
        kubernetes_snaps.service_restart = lambda name: log.debug("Deferred restart of %s", name)
        try:
            yield
        finally:
            kubernetes_snaps.service_restart = restart

        unit = f"snap.{service}.daemon"
        current = fingerprint(service, extra_files)
        if current == self.stored.fingerprints.get(service) and is_active(unit):
            log.info("No configuration change for %s, skipping restart", service)
            return
        status.add(ops.MaintenanceStatus(f"Restarting {service}"))
        log.info("Restarting %s", unit)
        restart(unit)
        self.stored.fingerprints[service] = current

    def ensure_restart_always(self, control_plane: bool = False):
        """Write the always-restart systemd drop-ins only when they are missing or stale."""
        services = ["kubelet", "kube-proxy"]
        if control_plane:
            services += ["kube-apiserver", "kube-controller-manager", "kube-scheduler"]
        drop_ins = (
            Path(f"/etc/systemd/system/snap.{service}.daemon.service.d/always-restart.conf")
            for service in services
        )
        if any(_read_text(p) != RESTART_ALWAYS_CONF for p in drop_ins):
            kubernetes_snaps.configure_services_restart_always(control_plane=control_plane)

    def service_has_failed(self, service: str) -> Tuple[bool, str]:
        """Check whether a systemd service has failed or is crash-looping.

        Only reports; systemd's Restart=always is responsible for restarting.
        """
        try:
            output = subprocess.check_output(
                ["systemctl", "show", "--no-pager", service], stderr=subprocess.STDOUT
            ).decode("utf-8")
        except subprocess.CalledProcessError as e:
            return True, f"Failed to check {service} status: {e.output.decode('utf-8')}"

        fields = dict(line.split("=", 1) for line in output.strip().splitlines() if "=" in line)
        active_state = fields.get("ActiveState")
        result = fields.get("Result")
        exec_main_status = fields.get("ExecMainStatus")
        n_restarts = int(fields.get("NRestarts") or 0)

        # NRestarts is cumulative, so only its growth since the last check matters
        previous = self.stored.restart_counts.get(service, n_restarts)
        self.stored.restart_counts[service] = n_restarts

        if active_state == "failed" or result == "exit-code":
            return True, f"{service} has failed: ActiveState={active_state}, Result={result}"
        elif exec_main_status and exec_main_status != "0":
            return True, f"{service} Non-zero exit: ExecMainStatus={exec_main_status}"
        elif n_restarts - previous > MAX_RESTARTS_BETWEEN_CHECKS:
            return True, f"{service} is restarting repeatedly"
        return False, ""
