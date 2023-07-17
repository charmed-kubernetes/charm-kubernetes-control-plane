# Copyright 2023 Canonical
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import unittest
from unittest.mock import patch

import ops
import ops.testing
from charm import KubernetesControlPlaneCharm


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = ops.testing.Harness(KubernetesControlPlaneCharm)
        self.addCleanup(self.harness.cleanup)

    @patch("charms.kubernetes_snaps.install")
    def test_start(self, kubernetes_snaps_install):
        self.harness.begin_with_initial_hooks()

        kubernetes_snaps_install.assert_called()
        self.assertEqual(self.harness.model.unit.status, ops.ActiveStatus())
