from unittest import mock

import hvac.adapters
import hvac.exceptions
import ops
import ops.testing
import pytest
from charm import KubernetesControlPlaneCharm
from vault_kv import VaultNotReadyError, retrieve_secret_id


@pytest.fixture
def harness():
    harness = ops.testing.Harness(KubernetesControlPlaneCharm)
    try:
        harness.add_network("10.0.0.10", endpoint="vault-kv")
        yield harness
    finally:
        harness.cleanup()


@pytest.fixture(autouse=True)
def mock_retrieve_secret_id():
    with mock.patch("vault_kv.retrieve_secret_id") as as_mock:
        as_mock.return_value = "secret-from-token-value"
        yield as_mock


@pytest.fixture(autouse=True)
def vault_kv(harness):
    """Mock vault kv endpoint."""
    harness.set_leader(True)
    harness.disable_hooks()
    harness.begin()
    harness.add_relation(
        "vault-kv",
        "vault",
        unit_data={
            "vault_url": "https://test.me:4040",
            f"{harness.charm.unit.name}_role_id": "test-role-id",
            f"{harness.charm.unit.name}_token": "some-secret-token-value",
        },
    )
    harness.add_relation("peer", "kubernetes-control-plane")
    yield harness.charm.vault_kv


@pytest.fixture(params=["", "charm-{app}", "charm-{model-uuid}-{app}"])
def backend_format(request, vault_kv):
    vault_kv._kwds["backend_format"] = request.param

    class Formatter(str):
        @property
        def expected(self):
            fmt = self
            if fmt == "":
                fmt = "charm-{model-uuid}-{app}"
            context = {
                "model-uuid": vault_kv.model.uuid,
                "app": vault_kv.model.app.name,
            }
            return fmt.format(**context)

    yield Formatter(request.param)


def test_get_vault_config_success(mock_retrieve_secret_id, vault_kv, backend_format):
    """Confirm vault config can be retrieved with valid relation data."""
    vault_config = vault_kv.get_vault_config(backend_format=backend_format)
    vault_kv_ifc = vault_kv.requires

    mock_retrieve_secret_id.assert_called_once_with(
        vault_kv_ifc.vault_url, vault_kv_ifc.unit_token
    )
    assert vault_kv._stored.token == "some-secret-token-value"
    assert vault_kv._stored.secret_id == "secret-from-token-value"
    assert vault_config == {
        "vault_url": vault_kv_ifc.vault_url,
        "secret_backend": backend_format.expected,
        "role_id": vault_kv_ifc.unit_role_id,
        "secret_id": "secret-from-token-value",
        "on_change": vault_kv.emit_changed_event,
    }


def test_get_vault_config_fails_get_secret_id(mock_retrieve_secret_id, harness, vault_kv):
    """Confirm vault failures transitions to VaultNotReady.

    Also confirm the kv storage and data_changed hash is only updated on
    successful retrieval using the one-time token from `secret_id`
    """
    mock_retrieve_secret_id.side_effect = hvac.exceptions.VaultDown()
    vault_kv._stored.token = "unchanged"
    vault_kv_ifc = vault_kv.requires
    with pytest.raises(VaultNotReadyError):
        vault_kv.get_vault_config()

    assert vault_kv._stored.token == "unchanged"
    mock_retrieve_secret_id.assert_called_once_with(
        vault_kv_ifc.vault_url, vault_kv_ifc.unit_token
    )


@mock.patch("hvac.Client", autospec=True)
def test_vault_app_kv(mock_client, vault_kv, backend_format):
    mock_client().read.return_value = {"data": {"gettable": "static"}}
    kv = vault_kv.app_kv
    assert mock_client().read.call_args_list == [
        mock.call(f"{backend_format.expected}/kv/app"),
        mock.call(f"{backend_format.expected}/kv/app-hashes/0"),
    ]

    assert kv._config["secret_backend"] == backend_format.expected

    # Nothing yet set
    assert kv.keys() == {"gettable"}
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

    assert dict(kv.items()) == {"settable": "new-value", "gettable": "static"}

    new_config = dict(**kv._config)
    new_config["secret-id"] = "super-secret"
    mock_client().read.reset_mock()
    kv.update_config(new_config)
    mock_client().read.assert_called_once_with(f"{backend_format.expected}/kv/app")
    assert dict(kv.items()) == {"settable": "new-value", "gettable": "static"}

    mock_client().write.reset_mock()
    event = mock.MagicMock()
    vault_kv._on_commit(event)
    mock_client().write.assert_called_once_with(
        f"{backend_format.expected}/kv/app-hashes/0",
        settable="634de56e57a47cafb4977a2bdcc5f175",
        gettable="6a60d7c16689e17a50f7305082958434",
    )


@mock.patch("hvac.Client", autospec=True)
def test_retrieve_secret_id(mock_client):
    response = mock_client.return_value.sys.unwrap()
    response.json.return_value = {"data": {"secret_id": "super-secret"}}
    response.status_code = 200
    secret_id = retrieve_secret_id("url", "token")
    assert secret_id == "super-secret"
    mock_client.assert_called_once_with(url="url", token="token", adapter=hvac.adapters.RawAdapter)

    response.status_code = 400
    secret_id = retrieve_secret_id("url", "token")
    assert secret_id is None


@mock.patch("socket.gethostname", mock.MagicMock(return_value="hostname"))
def test_vault_kv_relation_joined(harness, vault_kv):
    vault_kv._stored.secret_id = "secret-from-token-value"
    harness.enable_hooks()
    rel = harness.add_relation(
        "vault-kv",
        "vault-1",
        unit_data={
            "vault_url": "https://2.test.me:4040",
            f"{harness.charm.unit.name}_role_id": "test-role-id",
            f"{harness.charm.unit.name}_token": "some-secret-token-value",
        },
    )
    requested = harness.get_relation_data(rel, harness.charm.unit)
    assert requested == {
        "access_address": "10.0.0.10",
        "hostname": "hostname",
        "isolated": "false",
        "secret_backend": f"charm-{harness.model.uuid}-{harness.charm.app.name}",
        "unit_name": f"{harness.model.uuid}-{harness.charm.unit.name}",
    }
