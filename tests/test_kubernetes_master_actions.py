import base64
import json
import pytest
import sys
from unittest import mock


charms = mock.MagicMock()
sys.modules['charms'] = charms
sys.modules['charms.layer'] = charms.layer

from actions import user_actions  # noqa: E402


def test_protect_resources():
    """Verify exception when acting on protected resources."""
    with pytest.raises(SystemExit):
        user_actions.protect_resources('admin')
    with pytest.raises(SystemExit):
        user_actions.protect_resources('kubelet-X')


def test_user_list():
    """Verify user data is parsed correctly from our secrets."""
    user = 'admin'
    secret_id = '{}-secret'.format(user)

    test_data = {
        'items': [{
            'metadata': {
                'name': secret_id,
            },
            'data': {
                'username': base64.b64encode(user.encode('utf-8')).decode('utf-8'),
            }
        }]
    }
    secrets = json.dumps(test_data).encode('utf-8')

    # we expect a {username: secret_id} dict
    with mock.patch('actions.user_actions.layer.kubernetes_common.kubectl',
                    return_value=secrets):
        secret_data = user_actions.user_list()
        assert user in secret_data.keys()
        assert secret_id in secret_data.values()


@mock.patch('actions.user_actions.action_get')
def test_user_create(mock_get):
    """Verify failure if we create a user that already exists."""
    user = 'testuser'
    secret_id = '{}-secret'.format(user)
    test_data = {
        user: secret_id
    }

    mock_get.return_value = user
    with mock.patch('actions.user_actions.user_list',
                    return_value=test_data):
        user_actions.user_create()
        assert user_actions.action_fail.called


@mock.patch('actions.user_actions.action_get')
def test_user_delete(mock_get):
    """Verify failure if we delete a user that does not exist."""
    user = 'testuser'
    secret_id = '{}-secret'.format(user)
    test_data = {
        user: secret_id
    }

    mock_get.return_value = 'testuser2'
    with mock.patch('actions.user_actions.user_list',
                    return_value=test_data):
        user_actions.user_delete()
        assert user_actions.action_fail.called
