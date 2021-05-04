#!/usr/bin/env python3

import csv
import json
import logging
import aiohttp
from base64 import b64decode
from copy import deepcopy
from pathlib import Path
from subprocess import check_call, check_output, CalledProcessError, TimeoutExpired
from yaml import safe_load


AWS_IAM_ENDPOINT = '{{ aws_iam_endpoint if aws_iam_endpoint }}'
KEYSTONE_ENDPOINT = '{{ keystone_endpoint if keystone_endpoint }}'
CUSTOM_AUTHN_ENDPOINT = '{{ custom_authn_endpoint if custom_authn_endpoint }}'

app = aiohttp.web.Application()
routes = aiohttp.web.RouteTableDef()


def kubectl(*args):
    '''Run a kubectl cli command with a config file.

    Returns stdout and throws an error if the command fails.
    '''
    # Try to use our service account kubeconfig; fall back to root if needed
    kubectl_cmd = Path('/snap/bin/kubectl')
    if not kubectl_cmd.is_file():
        # Fall back to anywhere on the path if the snap isn't available
        kubectl_cmd = 'kubectl'
    kubeconfig = '/root/.kube/config'
    command = [str(kubectl_cmd), '--kubeconfig={}'.format(kubeconfig)] + list(args)
    return check_output(command, timeout=10)


def log_secret(text, obj, hide=True):
    '''Log information about a TokenReview object.

    The message will always be logged at the 'debug' level and will be in the
    form "text: obj". By default, secrets will be hidden. Set 'hide=False' to
    have the secret printed in the output unobfuscated.
    '''
    log_obj = obj
    if obj and hide:
        log_obj = deepcopy(obj)
        try:
            log_obj['spec']['token'] = '********'
        except (KeyError, TypeError):
            # No secret here, carry on
            pass
    app.logger.debug('{}: {}'.format(text, log_obj))


async def check_token(token_review):
    '''Populate user info if token is found in auth-related files.'''
    app.logger.info('Checking token')
    token_to_check = token_review['spec']['token']

    # If we have an admin token, short-circuit all other checks. This prevents us
    # from leaking our admin token to other authn services.
    admin_kubeconfig = Path('/root/.kube/config')
    if admin_kubeconfig.exists():
        with admin_kubeconfig.open('r') as f:
            data = safe_load(f)
            try:
                admin_token = data['users'][0]['user']['token']
            except (KeyError, ValueError):
                # No admin kubeconfig; this is weird since we should always have an
                # admin kubeconfig, but we shouldn't fail here in case there's
                # something in known_tokens that should be validated.
                pass
            else:
                if token_to_check == admin_token:
                    # We have a valid admin
                    token_review['status'] = {
                        'authenticated': True,
                        'user': {
                            'username': 'admin',
                            'uid': 'admin',
                            'groups': ['system:masters']
                        }
                    }
                    return True

    # No admin? We're probably in an upgrade. Check an existing known_tokens.csv.
    csv_fields = ['token', 'username', 'user', 'groups']
    known_tokens = Path('/root/cdk/known_tokens.csv')
    try:
        with known_tokens.open('r') as f:
            data_by_token = {r['token']: r for r in csv.DictReader(f, csv_fields)}
    except FileNotFoundError:
        data_by_token = {}

    if token_to_check in data_by_token:
        record = data_by_token[token_to_check]
        # groups are optional; default to an empty string if we don't have any
        groups = record.get('groups', '').split(',')
        token_review['status'] = {
            'authenticated': True,
            'user': {
                'username': record['username'],
                'uid': record['user'],
                'groups': groups,
            }
        }
        return True
    return False


async def check_secrets(token_review):
    '''Populate user info if token is found in k8s secrets.'''
    # Only check secrets if kube-apiserver is up
    try:
        output = check_call(['systemctl', 'is-active', 'snap.kube-apiserver.daemon'])
    except CalledProcessError:
        app.logger.info('Skipping secret check: kube-apiserver is not ready')
        return False
    else:
        app.logger.info('Checking secret')

    token_to_check = token_review['spec']['token']
    try:
        output = kubectl(
            'get', 'secrets', '-n', 'kube-system', '-o', 'json').decode('UTF-8')
    except (CalledProcessError, TimeoutExpired) as e:
        app.logger.info('Unable to load secrets: {}.'.format(e))
        return False

    secrets = json.loads(output)
    if 'items' in secrets:
        for secret in secrets['items']:
            try:
                data_b64 = secret['data']
                password_b64 = data_b64['password'].encode('UTF-8')
                username_b64 = data_b64['username'].encode('UTF-8')
            except (KeyError, TypeError):
                # CK secrets will have populated 'data', but not all secrets do
                continue

            password = b64decode(password_b64).decode('UTF-8')
            if token_to_check == password:
                groups_b64 = data_b64['groups'].encode('UTF-8') \
                    if 'groups' in data_b64 else b''

                # NB: CK creates k8s secrets with the 'password' field set as
                # uid::token. Split the decoded password so we can send a 'uid' back.
                # If there is no delimiter, set uid == username.
                # TODO: make the delimeter less magical so it doesn't get out of
                # sync with the function that creates secrets in k8s-master.py.
                username = uid = b64decode(username_b64).decode('UTF-8')
                pw_delim = '::'
                if pw_delim in password:
                    uid = password.rsplit(pw_delim, 1)[0]
                groups = b64decode(groups_b64).decode('UTF-8').split(',')
                token_review['status'] = {
                    'authenticated': True,
                    'user': {
                        'username': username,
                        'uid': uid,
                        'groups': groups,
                    }
                }
                return True
    return False


async def check_aws_iam(token_review):
    '''Check the request with an AWS IAM authn server.'''
    app.logger.info('Checking AWS IAM')

    # URL comes from /root/cdk/aws-iam-webhook.yaml
    app.logger.debug('Forwarding to: {}'.format(AWS_IAM_ENDPOINT))

    return await forward_request(token_review, AWS_IAM_ENDPOINT)


async def check_keystone(token_review):
    '''Check the request with a Keystone authn server.'''
    app.logger.info('Checking Keystone')

    # URL comes from /root/cdk/keystone/webhook.yaml
    app.logger.debug('Forwarding to: {}'.format(KEYSTONE_ENDPOINT))

    return await forward_request(token_review, KEYSTONE_ENDPOINT)


async def check_custom(token_review):
    '''Check the request with a user-specified authn server.'''
    app.logger.info('Checking Custom Endpoint')

    # User will set the URL in k8s-master config
    app.logger.debug('Forwarding to: {}'.format(CUSTOM_AUTHN_ENDPOINT))

    return await forward_request(token_review, CUSTOM_AUTHN_ENDPOINT)


async def forward_request(json_req, url):
    '''Forward a JSON TokenReview request to a url.

    Returns True if the request is authenticated; False if the response is
    either invalid or authn has been denied.
    '''
    timeout = 10
    resp_text = ''
    try:
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(url, json=json_req, timeout=timeout) as resp:
                    resp_text = await resp.text()
            except aiohttp.ClientSSLError:
                app.logger.debug('SSLError with server; skipping cert validation')
                async with session.post(url,
                                        json=json_req,
                                        verify_ssl=False,
                                        timeout=timeout) as resp:
                    resp_text = await resp.text()
    except Exception as e:
        app.logger.debug('Failed to contact server: {}'.format(e))
        return False

    # Check if the response is valid
    try:
        resp = json.loads(resp_text)
        'authenticated' in resp['status']
    except (KeyError, TypeError, ValueError):
        log_secret(text='Invalid response from server', obj=resp_text)
        return False

    # NB: When a forwarded request is authenticated, set the 'status' field to
    # whatever the external server sends us. This ensures any status fields that
    # the server wants to send makes it back to the kube apiserver.
    if resp['status']['authenticated']:
        json_req['status'] = resp['status']
        return True
    return False


def ack(req, **kwargs):
    # Successful checks will set auth and user data in the 'req' dict
    log_secret(text='ACK', obj=req)
    return aiohttp.web.json_response(req, **kwargs)


def nak(req, **kwargs):
    # Force unauthenticated, just in case
    req.setdefault('status', {})['authenticated'] = False
    log_secret(text='NAK', obj=req)
    return aiohttp.web.json_response(req, **kwargs)


@routes.post('/{{ api_ver }}')
async def webhook(request):
    '''Listen on /$api_version for POST requests.

    For a POSTed TokenReview object, check every known authentication mechanism
    for a user with a matching token.

    The /$api_version is expected to be the api version of the authentication.k8s.io
    TokenReview that the k8s-apiserver will be sending.

    Returns:
        TokenReview object with 'authenticated: True' and user attributes if a
        token is found; otherwise, a TokenReview object with 'authenticated: False'
    '''
    # Log to gunicorn
    glogger = logging.getLogger('gunicorn.error')
    app.logger.handlers = glogger.handlers
    app.logger.setLevel(glogger.level)

    req = await request.json()
    # Make the request unauthenticated by deafult
    req['status'] = {'authenticated': False}

    try:
        valid = True if (req['kind'] == 'TokenReview' and
                         req['spec']['token']) else False
    except (KeyError, TypeError):
        valid = False

    if valid:
        log_secret(text='REQ', obj=req)
    else:
        log_secret(text='Invalid request', obj=req)
        return nak({}, status=400)

    if await check_token(req):
        return ack(req)
    try:
        if await check_secrets(req):
            return ack(req)
    except Exception:
        app.logger.exception('Failed to get secrets')
        return nak(req)

    if AWS_IAM_ENDPOINT and await check_aws_iam(req):
        return ack(req)

    if KEYSTONE_ENDPOINT and await check_keystone(req):
        return ack(req)

    if CUSTOM_AUTHN_ENDPOINT and await check_custom(req):
        return ack(req)

    return nak(req)


app.add_routes(routes)


if __name__ == '__main__':
    app.run()
