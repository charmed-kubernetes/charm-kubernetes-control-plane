#!/usr/bin/env python3

import csv
import json
from base64 import b64decode
from flask import Flask, request, jsonify
from pathlib import Path
from subprocess import check_output
app = Flask(__name__)


def fetch_known_token_data(token):
    '''Fetch known_tokens.csv entry for a given token.

    Returns the csv line as a dict if the given token is found; otherwise,
    an empty dict.
    '''
    known_tokens = Path('/root/cdk/known_tokens.csv')
    csv_fields = ['token', 'username', 'user', 'groups']

    try:
        with known_tokens.open('r') as f:
            data_by_token = {r['token']: r for r in csv.DictReader(f, csv_fields)}
    except FileNotFoundError:
        data_by_token = {}

    if token in data_by_token:
        record = data_by_token[token]
    else:
        record = {}

    return record


def kubectl(*args):
    '''Run a kubectl cli command with a config file.

    Returns stdout and throws an error if the command fails.
    '''
    command = ['kubectl', '--kubeconfig=/root/.kube/config'] + list(args)
    return check_output(command)


def check_token(token_review):
    print('Checking token')
    token_data = fetch_known_token_data(token_review['spec']['token'])
    if token_data:
        token_review['status'] = {
            'authenticated': True,
            'user': {
                'username': token_data['username'],
                'uid': token_data['user'],
                'groups': token_data['groups'].split(','),
            }
        }
        return True
    return False


def check_secret(token_review):
    print('Checking secret')
    token_to_check = token_review['spec']['token']
    output = kubectl('get', 'secrets', '-o', 'json').decode('UTF-8')
    secrets = json.loads(output)
    if 'items' in secrets:
        for secret in secrets['items']:
            try:
                data_b64 = secret['data']
                token_b64 = data_b64['password'].encode('UTF-8')
            except (KeyError, TypeError):
                continue

            token = b64decode(token_b64).decode('UTF-8')
            if token == token_to_check:
                username_b64 = data_b64['username'].encode('UTF-8')
                user_b64 = data_b64['user'].encode('UTF-8')
                groups_b64 = data_b64['groups'].encode('UTF-8') \
                    if 'groups' in data_b64 else b''

                token_review['status'] = {
                    'authenticated': True,
                    'user': {
                        'username': b64decode(username_b64).decode('UTF-8'),
                        'uid': b64decode(user_b64).decode('UTF-8'),
                        'groups': b64decode(groups_b64).decode('UTF-8').split(','),
                    }
                }
                return True
    return False


def check_aws_iam(token_review):
    print('Checking AWS')
    return False


def check_keystone(token_review):
    print('Checking Keystone')
    return False


@app.route('/', methods=['POST'])
def webhook():
    '''Listen on / for POST requests.

    For a POSTed TokenReview object, check every known authentication mechanism
    for a user with a matching token.

    Returns:
        TokenReview object with 'user' attributes if a user is found; otherwise,
        an empty string.
    '''
    req = request.json
    try:
        valid = True if (req['kind'] == 'TokenReview' and
                         req['spec']['token']) else False
    except (KeyError, TypeError):
        valid = False

    if valid:
        # Make the request unauthenticated by deafult
        req['status'] = {'authenticated': False}
    else:
        print('Invalid request: {}'.format(req))
        return ''  # flask needs to return something that isn't None

    print('REQ: {}'.format(req))

    if (check_token(req) or check_secret(req) or
            check_aws_iam(req) or check_keystone(req)):
        print('RESP: {}'.format(req))
        return jsonify(req)
    else:
        print('No user found')
        return ''


if __name__ == '__main__':
    app.run()
