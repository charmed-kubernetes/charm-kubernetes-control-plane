#!/usr/bin/env python3

import csv
import json
from flask import Flask, request, jsonify
from pathlib import Path
from subprocess import check_output
app = Flask(__name__)


def fetch_token_data(token):
    '''Return user data for a given token.'''
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
    ''' Run a kubectl cli command with a config file. Returns stdout and throws
    an error if the command fails. '''
    command = ['kubectl', '--kubeconfig=/root/.kube/config'] + list(args)
    return check_output(command)


def check_token(token_review):
    print('Checking token')
    token_data = fetch_token_data(token_review['spec']['token'])
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
    password_to_check = token_review['spec']['token']
    output = kubectl('get', 'secrets', '-o', 'json').decode('UTF-8')
    secrets = json.loads(output)
    if 'items' in secrets:
        for item in secrets['items']:
            if 'data' in item:
                if 'password' in item['data']:
                    if item['data']['password'] == password_to_check:
                        token_review['status'] = {
                            'authenticated': True,
                            'user': {
                                'username': item['data']['username'],
                                'uid': item['data']['username'],
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


@app.route('/', methods=['POST'])  # Listen on / for POST requests
def webhook():
    req = request.json
    if 'kind' in req and req['kind'] == 'TokenReview':
        # Default to unauthenticated
        req['status'] = {'authenticated': False}
        print('REQ: {}'.format(req))
    else:
        print('Invalid TokenReview: {}'.format(req))
        return None

    if check_token(req):
        print('Found token')
    elif check_secret(req):
        print('Found secret')
    elif check_aws_iam(req):
        print('Found AWS')
    elif check_keystone(req):
        print('Found Keystone')

    print('RESP: {}'.format(req))
    return jsonify(req)


if __name__ == '__main__':
    app.run()
