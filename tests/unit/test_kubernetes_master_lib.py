import base64
import json
import pytest
import re
import tempfile
from pathlib import Path
from unittest import mock

from charmhelpers.core import hookenv
from lib.charms.layer import kubernetes_master as charmlib


@pytest.fixture
def auth_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir) / "test_auth.csv"


def test_deprecate_auth_file(auth_file):
    """Verify a comment is written to our auth file."""
    with mock.patch(
        "lib.charms.layer.kubernetes_master.Path.exists", return_value=True
    ):
        charmlib.deprecate_auth_file(auth_file)
    assert auth_file.read_text().startswith("#")


def test_migrate_auth_file(auth_file):
    """Verify migrating an auth token succeeds."""
    password = "password"
    user = "admin"
    auth_file.write_text("{},{},uid,group\n".format(password, user))

    # Create a known_token from basic_auth
    with mock.patch("lib.charms.layer.kubernetes_master.AUTH_BASIC_FILE", auth_file):
        with mock.patch("lib.charms.layer.kubernetes_master.create_known_token"):
            assert charmlib.migrate_auth_file(auth_file)

    # Create a secret from known_tokens
    with mock.patch("lib.charms.layer.kubernetes_master.AUTH_TOKENS_FILE", auth_file):
        with mock.patch("lib.charms.layer.kubernetes_master.create_secret"):
            assert charmlib.migrate_auth_file(auth_file)


@mock.patch("lib.charms.layer.kubernetes_master.render")
@mock.patch(
    "lib.charms.layer.kubernetes_master.kubernetes_common.kubectl_manifest",
    return_value=True,
)
@mock.patch("lib.charms.layer.kubernetes_master.get_secret_names", return_value={})
def test_create_secret(mock_secrets, mock_kubectl, mock_render):
    """Verify valid secret data is sent to kubectl during create."""
    password = "password"
    user_id = "replace$uid"
    secret_name = "replace-uid"
    secret_ns = "kube-system"
    secret_token = base64.b64encode(
        "{}::{}".format(user_id, password).encode("utf-8")
    ).decode("utf-8")

    charmlib.create_secret(password, "admin", user_id, "groupA,groupB")
    assert mock_kubectl.called
    args, kwargs = mock_render.call_args
    assert secret_name in kwargs["context"]["secret_name"]
    assert secret_ns in kwargs["context"]["secret_namespace"]
    assert secret_token in kwargs["context"]["password"]


@mock.patch(
    "lib.charms.layer.kubernetes_master.kubernetes_common.kubectl_success",
    return_value=True,
)
def test_delete_secret(mock_kubectl):
    """Verify valid secret data is sent to kubectl during delete."""
    secret_ns = "kube-system"

    # We should call kubectl with our namespace and return a bool
    assert charmlib.delete_secret("secret-id")
    args, kwargs = mock_kubectl.call_args
    assert secret_ns in args


def test_generate_rfc1123():
    """Verify genereated string is RFC 1123 compliant."""
    id = charmlib.generate_rfc1123()
    assert re.search("[^0-9a-z]+", id) is None


def test_get_csv_password(auth_file):
    """Verify expected content from an auth file is returned."""
    password = "password"
    user = "admin"

    # Test we handle a missing file
    with mock.patch(
        "lib.charms.layer.kubernetes_master.Path.is_file", return_value=False
    ):
        assert charmlib.get_csv_password("missing", user) is None

    # Test we handle a deprecated file
    auth_file.write_text("# Deprecated\n\n")
    assert charmlib.get_csv_password(auth_file, user) is None

    # Test we handle a valid file
    auth_file.write_text("{},{},uid,group\n".format(password, user))
    assert charmlib.get_csv_password(auth_file, user) == password


def test_get_secret_names():
    """Verify expected {username: secret_id} dict is returned."""
    secret = "mine"
    user = "admin"

    test_data = {
        "items": [
            {
                "data": {
                    "username": base64.b64encode(user.encode("utf-8")).decode("utf-8"),
                },
                "metadata": {
                    "name": secret,
                },
            }
        ]
    }
    secrets = json.dumps(test_data).encode("utf-8")

    # valid user should return a valid secret
    with mock.patch(
        "lib.charms.layer.kubernetes_master.kubernetes_common.kubectl",
        return_value=secrets,
    ):
        assert charmlib.get_secret_names()[user] == secret


def test_get_secret_password():
    """Verify expected secret token is returned."""
    password = "password"
    user = "admin"

    test_data = {
        "items": [
            {
                "data": {
                    "password": base64.b64encode(password.encode("utf-8")).decode(
                        "utf-8"
                    ),
                    "username": base64.b64encode(user.encode("utf-8")).decode("utf-8"),
                }
            }
        ]
    }
    secrets = json.dumps(test_data).encode("utf-8")

    # non-existent secret should return None
    with mock.patch(
        "lib.charms.layer.kubernetes_master.kubernetes_common.kubectl",
        return_value=secrets,
    ):
        assert charmlib.get_secret_password("missing") is None

    # known user should return our test data
    with mock.patch(
        "lib.charms.layer.kubernetes_master.kubernetes_common.kubectl",
        return_value=secrets,
    ):
        assert charmlib.get_secret_password(user) == password


def test_get_snap_revs():
    """Verify expected revision data."""
    channel = "test_channel"
    revision = "test_rev"
    snap = "test_snap"

    # empty test data should return a dict with None as the revision
    test_data = {}
    revs = json.dumps(test_data).encode("utf-8")
    with mock.patch(
        "lib.charms.layer.kubernetes_master.check_output", return_value=revs
    ):
        revs = charmlib.get_snap_revs([snap])
        assert revs[snap] is None

    # invalid test data should return a dict with None as the revision
    test_data = {"channels": {channel: "make indexerror"}}
    revs = json.dumps(test_data).encode("utf-8")
    hookenv.config.return_value = channel
    with mock.patch(
        "lib.charms.layer.kubernetes_master.check_output", return_value=revs
    ):
        revs = charmlib.get_snap_revs([snap])
        assert revs[snap] is None

    # valid test data should return a dict containing our test revision
    test_data = {"channels": {channel: "version date {} size notes".format(revision)}}
    revs = json.dumps(test_data).encode("utf-8")
    hookenv.config.return_value = channel
    with mock.patch(
        "lib.charms.layer.kubernetes_master.check_output", return_value=revs
    ):
        revs = charmlib.get_snap_revs([snap])
        assert revs[snap] == revision
