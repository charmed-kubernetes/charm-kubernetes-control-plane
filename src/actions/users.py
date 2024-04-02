#!/usr/local/sbin/charm-env python3
import os
import re

import ops
from auth_webhook import create_token, delete_token, get_secrets
from charms import kubernetes_snaps


def protect_resources(name: str, event: ops.ActionEvent) -> bool:
    """Do not allow the action to operate on names used by Charmed Kubernetes."""
    protected_names = [
        "admin",
        "system:kube-controller-manager",
        "kube-controller-manager",
        "system:kube-proxy",
        "kube-proxy",
        "system:kube-scheduler",
        "kube-scheduler",
        "system:monitoring",
    ]
    if name.startswith("kubelet") or name in protected_names:
        event.fail('Not allowed to {} "{}".'.format(event.id, name))
        return False
    return True


def user_list(event: ops.ActionEvent):
    """Return a dict of 'username: secret_id' for Charmed Kubernetes users."""
    secrets = list(get_secrets())
    event.set_results({"users": ", ".join(secrets)})
    return secrets


def user_create(charm, event: ops.ActionEvent):
    user = event.params["name"]
    groups = event.params.get("groups") or ""
    if not protect_resources(user, event):
        return

    users = user_list()
    if user in list(users):
        event.fail('User "{}" already exists.'.format(user))
        return

    # Validate the name
    if re.search("[^0-9A-Za-z:@.-]+", user):
        msg = "User name may only contain alphanumeric characters, ':', '@', '-' or '.'"
        event.fail(msg)
        return

    # Create the secret
    if not (token := create_token(user, user, groups)):
        event.fail("Failed to create secret for: {}".format(user))
        return

    if not (public_server := charm.k8s_api_endpoints.external()):
        event.fail("Kubernetes client endpoints currently unavailable.")

    # Create a kubeconfig
    ca = charm.certificates.ca
    kubeconfig_path = "/home/ubuntu/{}-kubeconfig".format(user)

    if not os.path.exists(kubeconfig_path):
        kubernetes_snaps.create_kubeconfig(
            kubeconfig_path,
            ca=ca,
            server=public_server,
            user=user,
            token=token,
        )

    os.chmod(kubeconfig_path, 0o644)

    # Tell the people what they've won
    fetch_cmd = "juju scp {}:{} .".format(event.framework.model.unit.name, kubeconfig_path)
    event.set_result(
        {
            "msg": 'User "{}" created.'.format(user),
            "users": ", ".join(list(users) + [user]),
            "kubeconfig": fetch_cmd,
        }
    )


def user_delete(event: ops.ActionEvent):
    user = event.params["name"]
    if not protect_resources(user, event):
        return

    users = user_list()
    if user not in list(users):
        event.fail('User "{}" does not exist.'.format(user))
        return

    # Delete the secret
    secret_id = users[user]
    delete_token(secret_id)

    event.set_results(
        {
            "msg": 'User "{}" deleted.'.format(user),
            "users": ", ".join(u for u in list(users) if u != user),
        }
    )
