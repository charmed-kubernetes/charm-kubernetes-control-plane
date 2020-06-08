import json
import socket
from pathlib import Path
from subprocess import check_output, CalledProcessError

from charmhelpers.core import hookenv
from charmhelpers.core.templating import render
from charmhelpers.fetch import apt_install
from charms.reactive import endpoint_from_flag, is_flag_set

from charms.layer import kubernetes_common


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
                            '-c', str(CEPH_CONF)])
        return bool(json.loads(out))
    except CalledProcessError:
        hookenv.log('Unable to determine if CephFS is enabled', 'ERROR')
        return False


def get_cephfs_fsname():
    install_ceph_common()
    data = json.loads(check_output(['ceph', 'fs', 'ls', '-f', 'json']))
    for fs in data:
        if 'ceph-fs_data' in fs['data_pools']:
            return fs['name']
