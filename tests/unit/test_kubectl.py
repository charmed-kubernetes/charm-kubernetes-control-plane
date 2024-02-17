from unittest.mock import patch

import kubectl


def test_kubectl():
    """Verify kubectl uses the appropriate kubeconfig files."""
    int_cfg = "--kubeconfig=/root/.kube/config"
    ext_cfg = "--kubeconfig=/home/ubuntu/config"

    with patch("kubectl.check_output") as mock:
        kubectl.kubectl()
        assert int_cfg in mock.call_args.args[0]

    with patch("kubectl.check_output") as mock:
        kubectl.kubectl(external=True)
        assert ext_cfg in mock.call_args.args[0]
