import pytest
from unittest import mock
from actions import user_actions


def test_protect_resources():
    """Verify exception when acting on protected resources."""
    with pytest.raises(SystemExit):
        user_actions.protect_resources("admin")
    with pytest.raises(SystemExit):
        user_actions.protect_resources("kubelet-X")


def test_user_list():
    """Verify user data is parsed correctly from our secrets."""
    user = secret_id = "admin"
    test_data = {user: secret_id}

    # we expect a {username: secret_id} dict
    with mock.patch(
        "actions.user_actions.layer.kubernetes_common.get_secret_names",
        return_value=test_data,
    ):
        secret_data = user_actions.user_list()
        assert user in secret_data.keys()
        assert secret_id in secret_data.values()


@mock.patch("actions.user_actions.os.chmod")
@mock.patch("actions.user_actions.layer.kubernetes_common")
@mock.patch("actions.user_actions.layer.kubernetes_master")
@mock.patch("actions.user_actions.action_get")
def test_user_create(mock_get, mock_master, mock_common, mock_chmod):
    """Verify expected calls are made when creating a user."""
    user = secret_id = "testuser"
    test_data = {user: secret_id}

    # Ensure failure when user exists
    mock_get.return_value = user
    with mock.patch("actions.user_actions.user_list", return_value=test_data):
        user_actions.user_create()
        assert user_actions.action_fail.called

    # Ensure failure when user name is invalid
    mock_get.return_value = "FunnyBu;sness"
    with mock.patch("actions.user_actions.user_list", return_value=test_data):
        user_actions.user_create()
        assert user_actions.action_fail.called

    # Ensure calls/args when we have a new user
    user = "newuser"
    password = "password"
    token = "{}::{}".format(user, password)
    mock_get.return_value = user
    mock_master.token_generator.return_value = password
    mock_master.get_api_endpoint.return_value = [1, 1]

    with mock.patch("actions.user_actions.user_list", return_value=test_data):
        user_actions.user_create()
    args, kwargs = mock_common.create_secret.call_args
    assert token in args
    args, kwargs = mock_common.create_kubeconfig.call_args
    assert token in kwargs["token"]


@mock.patch("actions.user_actions.layer.kubernetes_master")
@mock.patch("actions.user_actions.action_get")
def test_user_delete(mock_get, mock_master):
    """Verify expected calls are made when deleting a user."""
    user = secret_id = "testuser"
    test_data = {user: secret_id}

    # Ensure failure when user does not exist
    mock_get.return_value = "missinguser"
    with mock.patch("actions.user_actions.user_list", return_value=test_data):
        user_actions.user_delete()
        assert user_actions.action_fail.called

    # Ensure calls/args when we have a valid user
    mock_get.return_value = user

    with mock.patch("actions.user_actions.user_list", return_value=test_data):
        user_actions.user_delete()
    args, kwargs = mock_master.delete_secret.call_args
    assert secret_id in args
