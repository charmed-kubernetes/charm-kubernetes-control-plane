#!/usr/bin/env python3
# Copyright 2023 Canonical
# See LICENSE file for licensing details.

"""Charm."""

import logging

import ops
from charms import kubernetes_snaps
from charms.reconciler import Reconciler

log = logging.getLogger(__name__)


class KubernetesControlPlaneCharm(ops.CharmBase):
    """Charm."""

    def __init__(self, *args):
        super().__init__(*args)
        self.reconciler = Reconciler(self, self.reconcile)

    def reconcile(self, event):
        """Reconcile state change events."""
        kubernetes_snaps.install(channel=self.model.config["channel"], control_plane=True)


if __name__ == "__main__":  # pragma: nocover
    ops.main(KubernetesControlPlaneCharm)
