import csv
import json
import re
import socket
from base64 import b64decode
from pathlib import Path
from subprocess import check_output, CalledProcessError, TimeoutExpired

from charmhelpers.core import hookenv
from charmhelpers.core.templating import render
from charmhelpers.fetch import apt_install
from charms.reactive import endpoint_from_flag, is_flag_set
from charms.layer import kubernetes_common


AUTH_BASIC_FILE = '/root/cdk/basic_auth.csv'
AUTH_TOKENS_FILE = '/root/cdk/known_tokens.csv'
STANDARD_API_PORT = 6443
CEPH_CONF_DIR = Path('/etc/ceph')
CEPH_CONF = CEPH_CONF_DIR / 'ceph.conf'
CEPH_KEYRING = CEPH_CONF_DIR / 'ceph.client.admin.keyring'


def get_external_lb_endpoints():
    """
    Return a list of any external API load-balancer endpoints that have
    been manually configured.
    """
    ha_connected = is_flag_set('ha.connected')
    forced_lb_ips = hookenv.config('loadbalancer-ips').split()
    vips = hookenv.config('ha-cluster-vip').split()
    dns_record = hookenv.config('ha-cluster-dns')
    if forced_lb_ips:
        # if the user gave us IPs for the load balancer, assume
        # they know what they are talking about and use that
        # instead of our information.
        return [(address, STANDARD_API_PORT) for address in forced_lb_ips]
    elif ha_connected and vips:
        return [(vip, STANDARD_API_PORT) for vip in vips]
    elif ha_connected and dns_record:
        return [(dns_record, STANDARD_API_PORT)]
    else:
        return []


def get_lb_endpoints():
    """
    Return all load-balancer endpoints, whether from manual config or via
    relation.
    """
    external_lb_endpoints = get_external_lb_endpoints()
    loadbalancer = endpoint_from_flag('loadbalancer.available')

    if external_lb_endpoints:
        return external_lb_endpoints
    elif loadbalancer:
        lb_addresses = loadbalancer.get_addresses_ports()
        return [(host.get('public-address'), host.get('port'))
                for host in lb_addresses]
    else:
        return []


def get_api_endpoint(relation=None):
    """
    Determine the best endpoint for a client to connect to.

    If a relation is given, it will take that into account when choosing an
    endpoint.
    """
    endpoints = get_lb_endpoints()
    if endpoints:
        # select a single endpoint based on our local unit number
        return endpoints[kubernetes_common.get_unit_number() % len(endpoints)]
    elif relation:
        ingress_address = hookenv.ingress_address(relation.relation_id,
                                                  hookenv.local_unit())
        return (ingress_address, STANDARD_API_PORT)
    else:
        return (hookenv.unit_public_ip(), STANDARD_API_PORT)


def install_ceph_common():
    """Install ceph-common tools.

    :return: None
    """
    ceph_admin = endpoint_from_flag('ceph-storage.available')

    ceph_context = {
        'mon_hosts': ceph_admin.mon_hosts(),
        'fsid': ceph_admin.fsid(),
        'auth_supported': ceph_admin.auth(),
        'use_syslog': 'true',
        'ceph_public_network': '',
        'ceph_cluster_network': '',
        'loglevel': 1,
        'hostname': socket.gethostname(),
    }
    # Install the ceph common utilities.
    apt_install(['ceph-common'], fatal=True)

    CEPH_CONF_DIR.mkdir(exist_ok=True, parents=True)
    # Render the ceph configuration from the ceph conf template.
    render('ceph.conf', str(CEPH_CONF), ceph_context)

    # The key can rotate independently of other ceph config, so validate it.
    try:
        with open(str(CEPH_KEYRING), 'w') as key_file:
            key_file.write("[client.admin]\n\tkey = {}\n".format(
                ceph_admin.key()))
    except IOError as err:
        hookenv.log("IOError writing admin.keyring: {}".format(err))


def query_cephfs_enabled():
    install_ceph_common()
    try:
        out = check_output(['ceph', 'mds', 'versions',
                            '-c', str(CEPH_CONF)], timeout=60)
        return bool(json.loads(out.decode()))
    except CalledProcessError:
        hookenv.log('Unable to determine if CephFS is enabled', 'ERROR')
        return False
    except TimeoutExpired:
        hookenv.log('Timeout attempting to determine if CephFS is enabled', "ERROR")
        return False


def get_cephfs_fsname():
    install_ceph_common()
    try:
        data = json.loads(check_output(['ceph', 'fs', 'ls', '-f', 'json'], timeout=60))
    except TimeoutExpired:
        hookenv.log('Timeout attempting to determine fsname', "ERROR")
        return None
    for fs in data:
        if 'ceph-fs_data' in fs['data_pools']:
            return fs['name']


def deprecate_auth_file(auth_file):
    """
    In 1.19+, file-based authentication was deprecated in favor of webhook
    auth. Write out generic files that inform the user of this.
    """
    csv_file = Path(auth_file)
    csv_file.parent.mkdir(exist_ok=True)
    with csv_file.open('w') as f:
        f.write('# File-based authentication was deprecated in 1.19\n')


def migrate_auth_file(filename):
    migrate_basic = migrate_known_tokens = False
    if filename == AUTH_BASIC_FILE:
        migrate_basic = True
    elif filename == AUTH_TOKENS_FILE:
        migrate_known_tokens = True

    with open(filename, 'r') as f:
        rows = list(csv.reader(f))

    for row in rows:
        try:
            if row[0].startswith('#'):
                continue
            else:
                if migrate_basic:
                    create_known_token(*row)
                elif migrate_known_tokens:
                    create_secret(*row)
                else:
                    return False
        except IndexError:
            pass
    deprecate_auth_file(filename)
    return True


def create_known_token(token, username, user, groups=None):
    known_tokens = Path(AUTH_TOKENS_FILE)
    known_tokens.parent.mkdir(exist_ok=True)
    csv_fields = ['token', 'username', 'user', 'groups']

    try:
        with known_tokens.open('r') as f:
            tokens_by_user = {r['user']: r for r in csv.DictReader(f, csv_fields)}
    except FileNotFoundError:
        tokens_by_user = {}
    tokens_by_username = {r['username']: r for r in tokens_by_user.values()}

    if user in tokens_by_user:
        record = tokens_by_user[user]
    elif username in tokens_by_username:
        record = tokens_by_username[username]
    else:
        record = tokens_by_user[user] = {}
    record.update({
        'token': token,
        'username': username,
        'user': user,
        'groups': groups,
    })

    if not record['groups']:
        del record['groups']

    with known_tokens.open('w') as f:
        csv.DictWriter(f, csv_fields, lineterminator='\n').writerows(
            tokens_by_user.values())


def create_secret(token, username, user, groups=None):
    sani_name = re.sub('[^0-9a-zA-Z]+', '-', user)
    secret_id = '{}-secret'.format(sani_name)
    delete_secret(secret_id)
    kubernetes_common.kubectl('create', 'secret', 'generic', secret_id,
                              "--from-literal=username={}".format(username),
                              "--from-literal=groups={}".format(groups),
                              "--from-literal=password={}::{}".format(
                                  user, token))


def delete_secret(secret_id):
    try:
        kubernetes_common.kubectl('delete', 'secret', secret_id)
    except CalledProcessError:
        # Most probably a failure to delete an unknown secret; carry on.
        pass


def get_csv_password(csv_fname, user):
    """Get the password for the given user within the csv file provided."""
    root_cdk = '/root/cdk'
    tokens_fname = Path(root_cdk) / csv_fname
    if not tokens_fname.is_file:
        return None
    with open(tokens_fname, 'r') as stream:
        for line in stream:
            record = line.split(',')
            try:
                if record[1] == user:
                    return record[0]
            except IndexError:
                # probably a blank line or comment; move on
                continue
    return None


def get_secret_password(username):
    output = kubernetes_common.kubectl('get', 'secrets', '-o', 'json').decode('UTF-8')
    secrets = json.loads(output)
    if 'items' in secrets:
        for secret in secrets['items']:
            try:
                data_b64 = secret['data']
                password_b64 = data_b64['password'].encode('UTF-8')
                username_b64 = data_b64['username'].encode('UTF-8')
            except (KeyError, TypeError):
                # CK authn secrets will have populated 'data', but not all secrets do
                continue

            password = b64decode(password_b64).decode('UTF-8')
            secret_user = b64decode(username_b64).decode('UTF-8')
            if username == secret_user:
                return password
    return None
