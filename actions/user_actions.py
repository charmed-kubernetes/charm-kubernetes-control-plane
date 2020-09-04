#!/usr/local/sbin/charm-env python3
import json
import os
import sys
from base64 import b64decode
from charmhelpers.core import hookenv
from charmhelpers.core.hookenv import (
    action_get,
    action_set,
    action_fail,
    action_name
)
from charms import layer

os.environ['PATH'] += os.pathsep + os.path.join(os.sep, 'snap', 'bin')

# Import charm layers and start reactive
layer.import_layer_libs()
hookenv._run_atstart()


def protect_resources(name):
    '''Do not allow the action to operate on names used by Charmed Kubernetes.'''
    protected_names = ['admin',
                       'system:kube-controller-manager', 'kube-controller-manager',
                       'system:kube-proxy', 'kube-proxy',
                       'system:kube-scheduler', 'kube-scheduler',
                       'system:monitoring']
    if name.startswith('kubelet') or name in protected_names:
        action_fail('Not allowed to {} "{}".'.format(action, name))
        sys.exit(0)


def user_list():
    '''Return a dict of 'username: secret_id' for Charmed Kubernetes users.'''
    output = layer.kubernetes_common.kubectl(
        'get', 'secrets', '-n', layer.kubernetes_master.AUTH_SECRET_NS,
        '--field-selector', 'type={}'.format(layer.kubernetes_master.AUTH_SECRET_TYPE),
        '-o', 'json').decode('UTF-8')
    secrets = json.loads(output)
    users = {}
    if 'items' in secrets:
        for secret in secrets['items']:
            try:
                secret_id = secret['metadata']['name']
                username_b64 = secret['data']['username'].encode('UTF-8')
            except (KeyError, TypeError):
                # CK secrets will have populated 'data', but not all secrets do
                continue
            users[b64decode(username_b64).decode('UTF-8')] = secret_id
    action_set({'users': ', '.join(list(users))})
    return users


def user_create():
    user = action_get('name')
    groups = action_get('groups') or ''
    protect_resources(user)

    users = user_list()
    if user in list(users):
        action_fail('User "{}" already exists.'.format(user))
        return

    # Create the secret
    # TODO: make the token format less magical so it doesn't get out of
    # sync with the function that creates secrets in k8s-master.py.
    token = '{}::{}'.format(user, layer.kubernetes_master.token_generator())
    layer.kubernetes_master.create_secret(token, user, user, groups)

    # Create a kubeconfig
    ca_crt = layer.kubernetes_common.ca_crt_path
    kubeconfig_path = '/home/ubuntu/{}-kubeconfig'.format(user)
    public_address, public_port = layer.kubernetes_master.get_api_endpoint()
    public_server = 'https://{0}:{1}'.format(public_address, public_port)

    layer.kubernetes_common.create_kubeconfig(kubeconfig_path, public_server, ca_crt,
                                              token=token, user=user)
    os.chmod(kubeconfig_path, 0o644)

    # Tell the people what they've won
    fetch_cmd = 'juju scp {}:{} .'.format(hookenv.local_unit(), kubeconfig_path)
    action_set({'msg': 'User "{}" created.'.format(user)})
    action_set({'users': ', '.join(list(users) + [user])})
    action_set({'kubeconfig': fetch_cmd})


def user_delete():
    user = action_get('name')
    protect_resources(user)

    users = user_list()
    if user not in list(users):
        action_fail('User "{}" does not exist.'.format(user))
        return

    # Delete the secret
    secret_id = users[user]
    layer.kubernetes_master.delete_secret(secret_id)

    action_set({'msg': 'User "{}" deleted.'.format(user)})
    action_set({'users': ', '.join(u for u in list(users) if u != user)})


action = action_name().replace('user-', '')
if action == 'create':
    user_create()
elif action == 'list':
    user_list()
elif action == 'delete':
    user_delete()
