from base64 import b64encode
from unittest.mock import MagicMock, call, patch

import pytest

import auth_webhook


@pytest.fixture(autouse=True)
def fresh_cache():
    auth_webhook.clear_cache()
    yield
    auth_webhook.clear_cache()


def test_render_reports_change(tmp_path):
    dest = tmp_path / "auth-webhook.logrotate"
    context = {"logfile": "one.log"}
    assert auth_webhook.render("auth-webhook.logrotate", dest, context) is True
    mtime = dest.stat().st_mtime_ns
    assert auth_webhook.render("auth-webhook.logrotate", dest, context) is False
    assert dest.stat().st_mtime_ns == mtime
    assert auth_webhook.render("auth-webhook.logrotate", dest, {"logfile": "two.log"}) is True


@pytest.fixture
def configure_env(tmp_path):
    with (
        patch("auth_webhook.render") as render,
        patch("auth_webhook.is_active") as is_active,
        patch("auth_webhook._certs_changed") as certs_changed,
        patch("auth_webhook._save_certs_digest"),
        patch("auth_webhook.check_call") as check_call,
        patch("auth_webhook.check_output", MagicMock(return_value=b"2")),
        patch("auth_webhook.os.makedirs"),
        patch("auth_webhook.authz_webhook_conf", tmp_path / "authz.yaml"),
        patch("auth_webhook.ROOT_KUBECONFIG", MagicMock(**{"exists.return_value": False})),
        patch("auth_webhook._uplift_keystone_endpoint") as uplift,
    ):
        render.return_value = False
        is_active.return_value = True
        certs_changed.return_value = False
        yield render, is_active, certs_changed, check_call, uplift


def test_configure_unchanged_skips_restart(configure_env):
    _, _, _, check_call, uplift = configure_env
    auth_webhook.configure("/charm")
    check_call.assert_not_called()
    # No kubeconfig yet, so there is no API to ask about keystone
    uplift.assert_not_called()


def test_configure_unit_change_reloads_and_restarts(configure_env):
    render, _, _, check_call, _ = configure_env
    render.side_effect = lambda src, *_: src == "auth-webhook.service"
    auth_webhook.configure("/charm")
    assert check_call.call_args_list == [
        call(["systemctl", "daemon-reload"]),
        call(["systemctl", "restart", auth_webhook.auth_webhook_svc_name]),
    ]


def test_configure_cert_change_restarts(configure_env):
    _, _, certs_changed, check_call, _ = configure_env
    certs_changed.return_value = True
    auth_webhook.configure("/charm")
    check_call.assert_called_once_with(
        ["systemctl", "restart", auth_webhook.auth_webhook_svc_name]
    )


def test_configure_inactive_restarts(configure_env):
    _, is_active, _, check_call, _ = configure_env
    is_active.return_value = False
    auth_webhook.configure("/charm")
    check_call.assert_called_once_with(
        ["systemctl", "restart", auth_webhook.auth_webhook_svc_name]
    )


def test_certs_changed(tmp_path):
    cert = tmp_path / "server.crt"
    cert.write_text("cert")
    with (
        patch("auth_webhook.auth_webhook_certs", [str(cert)]),
        patch("auth_webhook.auth_webhook_certs_digest", tmp_path / ".digest"),
    ):
        assert auth_webhook._certs_changed()
        auth_webhook._save_certs_digest()
        assert not auth_webhook._certs_changed()
        cert.write_text("new-cert")
        assert auth_webhook._certs_changed()


def _secret(name, username, password):
    def b64(value):
        return b64encode(value.encode()).decode()

    return {
        "metadata": {"name": name},
        "data": {"username": b64(username), "password": b64(password)},
    }


@patch("auth_webhook.kubectl")
@patch("auth_webhook.kubectl_get")
def test_secrets_listed_once_per_reconcile(kubectl_get, kubectl):
    kubectl_get.return_value = {"items": [_secret("auth-admin", "admin", "admin::token")]}

    assert auth_webhook.get_token("admin") == "admin::token"
    assert auth_webhook.create_token("admin", "admin", ["system:masters"]) == "admin::token"
    token = auth_webhook.create_token("kube-proxy", "system:kube-proxy", [])
    assert auth_webhook.get_token("system:kube-proxy") == token
    kubectl_get.assert_called_once()
    kubectl.assert_called_once()  # the one `kubectl apply` for the new secret

    auth_webhook.delete_token("auth-admin")
    auth_webhook.get_token("admin")
    assert kubectl_get.call_count == 2
