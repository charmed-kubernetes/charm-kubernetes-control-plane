from unittest import mock

import pytest
import ops
import ops.testing
import hvac.exceptions

from charm import KubernetesControlPlaneCharm

from vault_kv import (
    VaultAppKV,
    VaultNotReadyError,
)


@pytest.fixture
def harness():
    harness = ops.testing.Harness(KubernetesControlPlaneCharm)
    try:
        harness.add_network("10.0.0.10", endpoint="kube-control")
        yield harness
    finally:
        harness.cleanup()



@pytest.fixture(autouse=True)
def vault(harness):
    """Mock vault kv endpoint"""
    harness.begin_with_initial_hooks()
    harness.disable_hooks()
    harness.add_relation("vault-kv", "vault", unit_data={
        "vault_url": "https://test.me:4040",
        f"{harness.charm.unit.name}_role_id": "test-role-id",
        f"{harness.charm.unit.name}_token": "some-secret-token-value"

    })
    yield harness.charm.vault_kv.requires


@pytest.fixture(params=["", "charm-{app}", "charm-{model-uuid}-{app}"])
def backend_format(request, harness: ops.testing.Harness):
    class Formatter(str):
        @property
        def expected(self):
            fmt = self
            if fmt == "":
                fmt = "charm-{model-uuid}-{app}"
            context = {
                "model-uuid": harness.model.uuid,
                "app": harness.model.app.name,
            }
            return fmt.format(**context)

    yield Formatter(request.param)


@mock.patch("vault_kv.retrieve_secret_id")
def test_get_vault_config_success(mock_rtv_secret_id, harness, vault, backend_format):
    """Confirm vault config can be retrieved with valid relation data."""
    mock_rtv_secret_id.return_value = "secret-from-token-value"
    vault_kv = harness.charm.vault_kv
    vault_config = vault_kv.get_vault_config(backend_format=backend_format)

    mock_rtv_secret_id.assert_called_once_with(vault.vault_url, vault.unit_token)
    assert harness.charm.vault_kv._stored.token == "some-secret-token-value"
    assert harness.charm.vault_kv._stored.secret_id == "secret-from-token-value"
    assert vault_config == {
        "vault_url": vault.vault_url,
        "secret_backend": backend_format.expected,
        "role_id": vault.unit_role_id,
        "secret_id": "secret-from-token-value",
    }


@mock.patch("vault_kv.retrieve_secret_id")
def test_get_vault_config_fails_get_secret_id(mock_rtv_secret_id, harness, vault):
    """
    Confirm vault failures transitions to VaultNotReady.

    Also confirm the kv storage and data_changed hash is only updated on
    successful retrieval using the one-time token from `secret_id`
    """
    mock_rtv_secret_id.side_effect = hvac.exceptions.VaultDown()
    vault_kv = harness.charm.vault_kv
    harness.charm.vault_kv._stored.token = "unchanged"
    with pytest.raises(VaultNotReadyError):
        vault_kv.get_vault_config()

    assert harness.charm.vault_kv._stored.token == "unchanged"
    mock_rtv_secret_id.assert_called_once_with(vault.vault_url, vault.unit_token)


@mock.patch("hvac.Client", autospec=True)
@mock.patch("vault_kv.retrieve_secret_id")
def test_vault_app_kv_singleton(mock_rtv_secret_id, mock_client, harness, backend_format):
    mock_client().read.return_value = dict(data={})
    mock_rtv_secret_id.return_value = "secret-from-token-value"
    VaultAppKV._singleton_instance = None
    kv = VaultAppKV(harness.charm.vault_kv, backend_format=backend_format)
    kv2 = VaultAppKV(harness.charm.vault_kv)

    assert kv is kv2, "Should be singleton instances"
    assert kv._config["secret_backend"] == backend_format.expected

    # Nothing yet set
    assert kv.keys() == set()
    mock_client().write.assert_not_called()

    kv["settable"] = "value"
    mock_client().write.assert_called_once_with(
        f"{backend_format.expected}/kv/app", settable="value"
    )
    mock_client().write.reset_mock()

    kv.set("settable", "new-value")
    mock_client().write.assert_called_once_with(
        f"{backend_format.expected}/kv/app", settable="new-value"
    )

    assert dict(kv.items()) == {"settable": "new-value"}
