from unittest.mock import MagicMock, patch

from cdk_addons import CdkAddons


@patch("cdk_addons.CdkAddons.set_default_storage_class")
@patch("cdk_addons.CdkAddons.apply")
@patch("cdk_addons.CdkAddons.copy_kubeconfig")
@patch("cdk_addons.check_call")
@patch("cdk_addons.arch", MagicMock(return_value="amd64"))
def test_apply_only_when_inputs_change(check_call, copy, apply, set_default, tmp_path):
    charm = MagicMock()
    charm.get_cluster_name.return_value = "k8s"
    charm.model.config = {
        "image-registry": "registry",
        "enable-dashboard-addons": True,
        "enable-metrics": True,
        "default-storage": "auto",
        "dns_domain": "cluster.local",
        "dns-provider": "auto",
    }
    kubeconfig = tmp_path / "config"
    kubeconfig.write_text("token-a")
    addons = CdkAddons(charm)

    with (
        patch("cdk_addons.ROOT_KUBECONFIG", kubeconfig),
        patch("cdk_addons.applied_digest_path", tmp_path / ".applied-digest"),
    ):
        addons.configure()
        addons.configure()
        assert apply.call_count == 1
        assert check_call.call_count == 1

        kubeconfig.write_text("token-b")
        addons.configure()
        assert apply.call_count == 2

        charm.model.config["enable-metrics"] = False
        addons.configure()
        assert apply.call_count == 3

    # the default storage class is reconciled every time; it's cheap and idempotent
    assert set_default.call_count == 4
