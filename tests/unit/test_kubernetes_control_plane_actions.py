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
@mock.patch("actions.user_actions.layer.kubernetes_control_plane")
@mock.patch("actions.user_actions.action_get")
def test_user_create(mock_get, mock_control_plane, mock_common, mock_chmod):
    """Verify expected calls are made when creating a user."""
    user = secret_id = "testuser"
    test_data = {user: secret_id}

    def make_api_url(endpoints):
        return ["https://{0}:{1}".format(*endpoint) for endpoint in endpoints]

    # Ensure failure when user exists
    mock_get.return_value = user
    with mock.patch("actions.user_actions.user_list", return_value=test_data):
        user_actions.user_create()
        assert user_actions.action_fail.called
        user_actions.action_fail.reset_mock()

    # Ensure failure when user name is invalid
    mock_get.return_value = "FunnyBu;sness"
    with mock.patch("actions.user_actions.user_list", return_value=test_data):
        user_actions.user_create()
        assert user_actions.action_fail.called
        user_actions.action_fail.reset_mock()

    # Ensure calls/args when we have a new user
    user = "newuser"
    password = "password"
    token = "{}::{}".format(user, password)
    mock_get.return_value = user
    mock_control_plane.token_generator.return_value = password
    mock_control_plane.get_external_api_endpoints.return_value = []
    with mock.patch("actions.user_actions.user_list", return_value=test_data):
        user_actions.user_create()
        assert user_actions.action_fail.called
        user_actions.action_fail.reset_mock()

    mock_control_plane.get_external_api_endpoints.return_value = [("test", 1234)]
    mock_control_plane.get_api_urls.side_effect = make_api_url

    with mock.patch("actions.user_actions.user_list", return_value=test_data):
        user_actions.user_create()
    args, kwargs = mock_control_plane.create_secret.call_args
    assert token in args
    args, kwargs = mock_common.create_kubeconfig.call_args
    assert args[0] == "/home/ubuntu/newuser-kubeconfig"
    assert args[1] == "https://test:1234"
    assert token in kwargs["token"]


@mock.patch("actions.user_actions.layer.kubernetes_control_plane")
@mock.patch("actions.user_actions.action_get")
def test_user_delete(mock_get, mock_control_plane):
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
    args, kwargs = mock_control_plane.delete_secret.call_args
    assert secret_id in args
