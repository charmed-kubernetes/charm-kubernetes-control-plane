import json
import pytest
import tempfile
from pathlib import Path
from unittest import mock
import unittest

from charmhelpers.core import hookenv
from lib.charms.layer import kubernetes_control_plane as charmlib


@pytest.fixture
def auth_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir) / "test_auth.csv"


def test_deprecate_auth_file(auth_file):
    """Verify a comment is written to our auth file."""
    with mock.patch(
        "lib.charms.layer.kubernetes_control_plane.Path.exists", return_value=True
    ):
        charmlib.deprecate_auth_file(auth_file)
    assert auth_file.read_text().startswith("#")


def test_migrate_auth_file(auth_file):
    """Verify migrating an auth token succeeds."""
    password = "password"
    user = "admin"
    auth_file.write_text("{},{},uid,group\n".format(password, user))

    # Create a known_token from basic_auth
    with mock.patch(
        "lib.charms.layer.kubernetes_control_plane.AUTH_BASIC_FILE", auth_file
    ):
        with mock.patch("lib.charms.layer.kubernetes_control_plane.create_known_token"):
            assert charmlib.migrate_auth_file(auth_file)

    # Create a secret from known_tokens
    with mock.patch(
        "lib.charms.layer.kubernetes_control_plane.AUTH_TOKENS_FILE", auth_file
    ):
        with mock.patch("lib.charms.layer.kubernetes_control_plane.create_secret"):
            assert charmlib.migrate_auth_file(auth_file)


@mock.patch(
    "lib.charms.layer.kubernetes_control_plane.AUTH_SECRET_NS", new="kube-system"
)
@mock.patch(
    "lib.charms.layer.kubernetes_control_plane.kubernetes_common.kubectl_success",
    return_value=True,
)
def test_delete_secret(mock_kubectl):
    """Verify valid secret data is sent to kubectl during delete."""
    secret_ns = "kube-system"

    # We should call kubectl with our namespace and return a bool
    assert charmlib.delete_secret("secret-id")
    args, kwargs = mock_kubectl.call_args
    assert secret_ns in args


def test_get_csv_password(auth_file):
    """Verify expected content from an auth file is returned."""
    password = "password"
    user = "admin"

    # Test we handle a missing file
    with mock.patch(
        "lib.charms.layer.kubernetes_control_plane.Path.is_file", return_value=False
    ):
        assert charmlib.get_csv_password("missing", user) is None

    # Test we handle a deprecated file
    auth_file.write_text("# Deprecated\n\n")
    assert charmlib.get_csv_password(auth_file, user) is None

    # Test we handle a valid file
    auth_file.write_text("{},{},uid,group\n".format(password, user))
    assert charmlib.get_csv_password(auth_file, user) == password


def test_get_snap_revs():
    """Verify expected revision data."""
    channel = "test_channel"
    revision = "test_rev"
    snap = "test_snap"

    # empty test data should return a dict with None as the revision
    test_data = {}
    revs = json.dumps(test_data).encode("utf-8")
    with mock.patch(
        "lib.charms.layer.kubernetes_control_plane.check_output", return_value=revs
    ):
        revs = charmlib.get_snap_revs([snap])
        assert revs[snap] is None

    # invalid test data should return a dict with None as the revision
    test_data = {"channels": {channel: "make indexerror"}}
    revs = json.dumps(test_data).encode("utf-8")
    hookenv.config.return_value = channel
    with mock.patch(
        "lib.charms.layer.kubernetes_control_plane.check_output", return_value=revs
    ):
        revs = charmlib.get_snap_revs([snap])
        assert revs[snap] is None

    # valid test data should return a dict containing our test revision
    test_data = {"channels": {channel: "version date {} size notes".format(revision)}}
    revs = json.dumps(test_data).encode("utf-8")
    hookenv.config.return_value = channel
    with mock.patch(
        "lib.charms.layer.kubernetes_control_plane.check_output", return_value=revs
    ):
        revs = charmlib.get_snap_revs([snap])
        assert revs[snap] == revision


def test_get_lb_port():
    """Verify correct lb port is returned"""
    # Test no custom ports
    hookenv.config.return_value = None
    assert charmlib.get_lb_port("internal") == charmlib.STANDARD_API_PORT
    assert charmlib.get_lb_port("external") == charmlib.EXTERNAL_API_PORT

    # Test custom internal lb port
    hookenv.config.return_value = 9999
    assert charmlib.get_lb_port("internal") == 9999

    # Test custom external lb port
    hookenv.config.return_value = 8888
    assert charmlib.get_lb_port("external") == 8888

    # Test wrong parameter
    testcase = unittest.TestCase()
    with testcase.assertRaises(NameError):
        charmlib.get_lb_port("dummy")


@mock.patch(
    "lib.charms.layer.kubernetes_control_plane.get_endpoints_from_config",
    return_value=None,
)
def test_get_external_api_endpoints(mock1):
    """Verify correct external endpoint is returned"""
    # No lb config, no custom lb port
    hookenv.unit_public_ip.return_value = "10.10.10.10"
    hookenv.goal_state.return_value = {"relations": {}}
    with mock.patch(
        "lib.charms.layer.kubernetes_control_plane.get_lb_port",
        return_value=charmlib.EXTERNAL_API_PORT,
    ):
        assert charmlib.get_external_api_endpoints() == [
            ("10.10.10.10", charmlib.STANDARD_API_PORT)
        ]
    # No lb config, custom lb port
    with mock.patch(
        "lib.charms.layer.kubernetes_control_plane.get_lb_port",
        return_value=9443,
    ):
        assert charmlib.get_external_api_endpoints() == [
            ("10.10.10.10", charmlib.STANDARD_API_PORT)
        ]

    # External lb configured
    hookenv.goal_state.return_value = {"relations": {"loadbalancer-external": {}}}
    with mock.patch(
        "lib.charms.layer.kubernetes_control_plane.endpoint_from_name"
    ) as mock_endpoint:
        endpoint = mock_endpoint.return_value
        endpoint.get_response.return_value.address = "192.168.0.1"
        endpoint.get_response.return_value.error = None
        # No custom lb port
        with mock.patch(
            "lib.charms.layer.kubernetes_control_plane.get_lb_port",
            return_value=charmlib.EXTERNAL_API_PORT,
        ):
            assert charmlib.get_external_api_endpoints() == [
                ("192.168.0.1", charmlib.EXTERNAL_API_PORT)
            ]
        # Custom lb port
        with mock.patch(
            "lib.charms.layer.kubernetes_control_plane.get_lb_port",
            return_value=9443,
        ):
            assert charmlib.get_external_api_endpoints() == [("192.168.0.1", 9443)]


@mock.patch(
    "lib.charms.layer.kubernetes_control_plane.get_endpoints_from_config",
    return_value=None,
)
def test_get_internal_api_endpoints(mock1):
    """Verify correct internal endpoint is returned"""
    # No lb config, no custom lb port
    hookenv.unit_public_ip.return_value = "10.10.10.10"
    hookenv.goal_state.return_value = {"relations": {}}
    with mock.patch(
        "lib.charms.layer.kubernetes_control_plane.get_lb_port",
        return_value=charmlib.STANDARD_API_PORT,
    ):
        assert charmlib.get_external_api_endpoints() == [
            ("10.10.10.10", charmlib.STANDARD_API_PORT)
        ]
    # No lb config, custom lb port
    with mock.patch(
        "lib.charms.layer.kubernetes_control_plane.get_lb_port",
        return_value=8443,
    ):
        assert charmlib.get_external_api_endpoints() == [
            ("10.10.10.10", charmlib.STANDARD_API_PORT)
        ]

    # Test external lb configured
    hookenv.goal_state.return_value = {"relations": {"loadbalancer-internal": {}}}
    with mock.patch(
        "lib.charms.layer.kubernetes_control_plane.endpoint_from_name"
    ) as mock_endpoint:
        endpoint = mock_endpoint.return_value
        endpoint.get_response.return_value.address = "192.168.0.1"
        endpoint.get_response.return_value.error = None
        # No custom external lb port
        with mock.patch(
            "lib.charms.layer.kubernetes_control_plane.get_lb_port",
            return_value=charmlib.STANDARD_API_PORT,
        ):
            assert charmlib.get_internal_api_endpoints() == [
                ("192.168.0.1", charmlib.STANDARD_API_PORT)
            ]
        # Custom external lb port
        with mock.patch(
            "lib.charms.layer.kubernetes_control_plane.get_lb_port",
            return_value=9443,
        ):
            assert charmlib.get_internal_api_endpoints() == [("192.168.0.1", 9443)]
