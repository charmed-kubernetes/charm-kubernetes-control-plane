import subprocess
import unittest.mock as mock

import kubectl
import pytest
import tenacity


@pytest.fixture(params=["/root/.kube/config", "/home/ubuntu/config"])
def kubeconfig(request):
    with mock.patch("pathlib.Path.exists") as exists:
        exists.return_value = True
        yield request.param, (request.param == "/home/ubuntu/config")


@mock.patch("pathlib.Path.exists")
def test_kubectl_no_kubeconfig(exists):
    """Verify kubectl fails immediately when there's no kubeconfig."""
    exists.return_value = False
    kubectl.kubectl.retry.wait = tenacity.wait_none()
    kubectl.kubectl.retry.stop = tenacity.stop_after_attempt(3)
    with pytest.raises(FileNotFoundError):
        kubectl.kubectl("get", "svc", "my-service")


@pytest.mark.usefixtures("kubeconfig")
def test_kubectl_retried():
    """Verify kubectl retries on failure."""
    with mock.patch("kubectl.check_output") as check_output:
        kubectl.kubectl.retry.wait = tenacity.wait_none()
        kubectl.kubectl.retry.stop = tenacity.stop_after_attempt(3)
        check_output.side_effect = subprocess.CalledProcessError(
            1, "kubectl", b"stdout", b"stderr"
        )
        with pytest.raises(subprocess.CalledProcessError):
            kubectl.kubectl("get", "svc", "my-service")
        assert check_output.call_count == 3


def test_kubectl_external(kubeconfig):
    """Verify kubectl uses the appropriate kubeconfig files."""
    path, external = kubeconfig

    with mock.patch("kubectl.check_output") as check_output:
        kubectl.kubectl("apply", "-f", "test.yaml", external=external)
        check_output.assert_called_once_with(
            ["kubectl", f"--kubeconfig={path}", "apply", "-f", "test.yaml"]
        )


def test_kubectl_get():
    """Verify kubectl_get parses kubectl results."""
    with mock.patch("kubectl.kubectl") as m_kubectl:
        m_kubectl.return_value = '{"kind": "Service", "metadata": {"name": "my-service"}}'
        value = kubectl.kubectl_get("svc", "my-service")
        m_kubectl.assert_called_once_with("get", "-o", "json", "svc", "my-service")
        assert value == {"kind": "Service", "metadata": {"name": "my-service"}}

        m_kubectl.return_value = ""
        value = kubectl.kubectl_get("svc", "my-service")
        assert value == {}


def test_get_service_ip():
    """Verify get_service_ip parses kubectl results."""
    with mock.patch("kubectl.kubectl_get") as m_kubectl_get:
        m_kubectl_get.return_value = {"kind": "Service", "spec": {"clusterIP": "1.2.3.4"}}
        value = kubectl.get_service_ip("my-service", "my-namespace")
        assert value == "1.2.3.4"
