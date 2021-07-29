import json
import pytest
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


@mock.patch("lib.charms.layer.kubernetes_master.AUTH_SECRET_NS", new="kube-system")
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
