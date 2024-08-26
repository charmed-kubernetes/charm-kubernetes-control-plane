import unittest.mock as mock
from pathlib import Path

import pytest
import yaml

import k8s_kube_system


@pytest.fixture
def get_pods():
    path = Path("tests/data/kube-system-pods.yaml")
    with mock.patch("k8s_kube_system.get_pods") as get_pods:
        get_pods.return_value = yaml.safe_load(path.open())
        yield get_pods


def test_get_kube_system_pods_not_running(get_pods):
    # This test is incomplete. You need to complete it.
    charm = mock.MagicMock()
    charm.config = {"ignore-kube-system-pods": "kube-state-metrics"}
    pods = k8s_kube_system.get_kube_system_pods_not_running(charm)
    assert len(pods) == 3
    get_pods.assert_called_once_with("kube-system")
    pod_names = [pod["metadata"]["name"] for pod in pods]
    assert pod_names[0] == "cilium-bbm6t"
    assert pod_names[2] == "metrics-server-v0.7.1-6c77d69467-24bh9"
