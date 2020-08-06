#!/usr/bin/env python3

import csv
import json
import logging
from base64 import b64decode
from flask import Flask, request, jsonify
from pathlib import Path
from subprocess import check_output, CalledProcessError
app = Flask(__name__)


def kubectl(*args):
    '''Run a kubectl cli command with a config file.

    Returns stdout and throws an error if the command fails.
    '''
    # Try to use our service account kubeconfig; fall back to root if needed
    kubeconfig = Path('/root/cdk/auth-webhook/kubeconfig')
    if not kubeconfig.exists():
        kubeconfig = Path('/root/.kube/config')
    command = ['kubectl', '--kubeconfig={}'.format(kubeconfig)] + list(args)
    return check_output(command)


def check_known_tokens(token_review):
    '''Populate user info if token is found in known_tokens.csv.'''
    app.logger.info('Checking token')
    token_to_check = token_review['spec']['token']

    csv_fields = ['token', 'username', 'user', 'groups']
    known_tokens = Path('/root/cdk/known_tokens.csv')
    try:
        with known_tokens.open('r') as f:
            data_by_token = {r['token']: r for r in csv.DictReader(f, csv_fields)}
    except FileNotFoundError:
        data_by_token = {}

    if token_to_check in data_by_token:
        record = data_by_token[token_to_check]
        token_review['status'] = {
            'authenticated': True,
            'user': {
                'username': record['username'],
                'uid': record['user'],
                'groups': record['groups'].split(','),
            }
        }
        return True
    return False


def check_secrets(token_review):
    '''Populate user info if token is found in k8s secrets.'''
    app.logger.info('Checking secret')
    token_to_check = token_review['spec']['token']

    try:
        output = kubectl(
            '-n', 'auth-webhook', 'get', 'secrets', '-o', 'json').decode('UTF-8')
    except CalledProcessError as e:
        app.logger.info('Unable to load secrets: {}.'.format(e))
        return False

    secrets = json.loads(output)
    if 'items' in secrets:
        for secret in secrets['items']:
            try:
                data_b64 = secret['data']
                password_b64 = data_b64['password'].encode('UTF-8')
            except (KeyError, TypeError):
                # CK secrets will have populated 'data', but not all secrets do
                continue

            password = b64decode(password_b64).decode('UTF-8')
            if token_to_check == password:
                username_b64 = data_b64['username'].encode('UTF-8')
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
                    uid = password.split(pw_delim)[0]
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


def check_aws_iam(token_review):
    app.logger.info('Checking AWS')
    return False


def check_keystone(token_review):
    '''Check the request with an external Keystone server.'''
    app.logger.info('Checking Keystone')
    app.logger.debug('Forwarding to: {{ keystone_service_cluster_ip }}')

    # URL is what CK has always used from keystone-api-server-webhook.yaml
    url = 'https://{{ keystone_service_cluster_ip }}:8443/webhook'
    try:
        try:
            r = requests.post(url, json=token_review)
        except requests.exceptions.SSLError:
            app.logger.debug('SSLError with Keystone; skipping cert validation')
            r = requests.post(url, json=token_review, verify=False)
    except Exception as e:
        app.logger.debug('Failed to contact the Keystone server: {}'.format(e))
        return False

    # Check if the response is valid
    try:
        ks_resp = json.loads(r.text)
        'authenticated' in ks_resp['status']
    except (KeyError, TypeError, ValueError) as e:
        app.logger.debug('Invalid response from Keystone: {}'.format(r.text))
        return False

    # If authenticated, overwrite our 'req' dict with Keystone's response
    if ks_resp['status']['authenticated']:
        token_review = ks_resp
        return True
    return False


@app.route('/{{ api_ver }}', methods=['POST'])
def webhook():
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

    req = request.json
    try:
        valid = True if (req['kind'] == 'TokenReview' and
                         req['spec']['token']) else False
    except (KeyError, TypeError):
        valid = False

    if valid:
        app.logger.debug('REQ: {}'.format(req))
    else:
        app.logger.info('Invalid request: {}'.format(req))
        return ''  # flask needs to return something that isn't None

    # Make the request unauthenticated by deafult
    req['status'] = {'authenticated': False}

    if (
        check_known_tokens(req)
        or check_secrets(req)
        {%- if keystone_service_cluster_ip %}
        or check_aws_iam(req)
        {%- endif %}
        {%- if keystone_service_cluster_ip %}
        or check_keystone(req)
        {%- endif %}
       ):
        # Successful checks will set auth and user data in the 'req' dict
        app.logger.debug('ACK: {}'.format(req))
    else:
        app.logger.debug('NAK: {}'.format(req))

    return jsonify(req)


if __name__ == '__main__':
    app.run()
