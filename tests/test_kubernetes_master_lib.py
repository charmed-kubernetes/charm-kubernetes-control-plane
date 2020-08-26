import base64
import json
import pytest
import tempfile
from pathlib import Path
from unittest import mock

from lib.charms.layer import kubernetes_master as charmlib


@pytest.fixture
def auth_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir) / 'test_auth.csv'


def test_deprecate_auth_file(auth_file):
    """Verify a comment is written to our auth file."""
    with mock.patch('lib.charms.layer.kubernetes_master.Path.exists',
                    return_value=True):
        charmlib.deprecate_auth_file(auth_file)
    assert auth_file.read_text().startswith('#')


def test_migrate_auth_file(auth_file):
    """Verify migrating an auth token succeeds."""
    password = 'password'
    user = 'admin'
    auth_file.write_text('{},{},uid,group\n'.format(password, user))

    # Create a known_token from basic_auth
    with mock.patch('lib.charms.layer.kubernetes_master.AUTH_BASIC_FILE',
                    auth_file):
        with mock.patch('lib.charms.layer.kubernetes_master.create_known_token'):
            assert charmlib.migrate_auth_file(auth_file)

    # Create a secret from known_tokens
    with mock.patch('lib.charms.layer.kubernetes_master.AUTH_TOKENS_FILE',
                    auth_file):
        with mock.patch('lib.charms.layer.kubernetes_master.create_secret'):
            assert charmlib.migrate_auth_file(auth_file)


@mock.patch('lib.charms.layer.kubernetes_master.render')
@mock.patch('lib.charms.layer.kubernetes_master.kubernetes_common.kubectl_manifest',
            return_value=True)
def test_create_secret(mock_kubectl, mock_render):
    """Verify valid secret data is sent to kubectl during create."""
    password = 'password'
    user_id = 'replace$uid'
    secret_name = 'replace-uid'
    secret_ns = 'kube-system'
    secret_token = base64.b64encode(
        '{}::{}'.format(user_id, password).encode('utf-8')).decode('utf-8')

    charmlib.create_secret(password, 'admin', user_id, 'groupA,groupB')
    assert mock_kubectl.called
    args, kwargs = mock_render.call_args
    assert secret_name in kwargs['context']['secret_name']
    assert secret_ns in kwargs['context']['secret_namespace']
    assert secret_token in kwargs['context']['password']


@mock.patch('lib.charms.layer.kubernetes_master.kubernetes_common.kubectl_success',
            return_value=True)
def test_delete_secret(mock_kubectl):
    """Verify valid secret data is sent to kubectl during delete."""
    secret_ns = 'kube-system'

    # We should call kubectl with our namespace and return a bool
    assert charmlib.delete_secret('secret-id')
    args, kwargs = mock_kubectl.call_args
    assert secret_ns in args


def test_get_csv_password(auth_file):
    """Verify expected content from an auth file is returned."""
    password = 'password'
    user = 'admin'

    # Test we handle a missing file
    with mock.patch('lib.charms.layer.kubernetes_master.Path.is_file',
                    return_value=False):
        assert charmlib.get_csv_password('missing', user) is None

    # Test we handle a deprecated file
    auth_file.write_text('# Deprecated\n\n')
    assert charmlib.get_csv_password(auth_file, user) is None

    # Test we handle a valid file
    auth_file.write_text('{},{},uid,group\n'.format(password, user))
    assert charmlib.get_csv_password(auth_file, user) == password


def test_get_secret_password():
    """Verify expected secret token is returned."""
    password = 'password'
    user = 'admin'

    test_data = {
        'items': [{
            'data': {
                'password': base64.b64encode(password.encode('utf-8')).decode('utf-8'),
                'username': base64.b64encode(user.encode('utf-8')).decode('utf-8'),
            }
        }]
    }
    secrets = json.dumps(test_data).encode('utf-8')

    # non-existent secret should return None
    with mock.patch('lib.charms.layer.kubernetes_master.kubernetes_common.kubectl',
                    return_value=secrets):
        assert charmlib.get_secret_password('missing') is None

    # known user should return our test data
    with mock.patch('lib.charms.layer.kubernetes_master.kubernetes_common.kubectl',
                    return_value=secrets):
        assert charmlib.get_secret_password(user) == password
