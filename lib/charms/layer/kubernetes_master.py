import json
from pathlib import Path
from subprocess import check_output, CalledProcessError
from tempfile import TemporaryDirectory

from charmhelpers.core import hookenv
from charms.reactive import endpoint_from_flag, is_flag_set, set_flag

from charms.layer import basic
from charms.layer import kubernetes_common


STANDARD_API_PORT = 6443


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


def query_cephfs_enabled(ceph_ep):
    if not is_flag_set('kubernetes-master.ceph-cli.installed'):
        basic.apt_install(['ceph-common'])
        set_flag('kubernetes-master.ceph-cli.installed')
    ceph_config = {
        'hosts': ceph_ep.mon_hosts(),
        'key': ceph_ep.key(),
        'auth': ceph_ep.auth(),
    }
    with TemporaryDirectory() as tmpdir:
        conf_file = Path(tmpdir) / 'ceph.conf'
        conf_file.write_text(
            '[global]\n'
            'mon_host = {hosts}\n'
            'key = {key}\n'
            'auth cluster required = {auth}\n'
            'auth service required = {auth}\n'
            'auth client required = {auth}\n'.format(**ceph_config))
        try:
            out = check_output(['ceph', 'mds', 'versions',
                                '-c', str(conf_file)])
            return bool(json.loads(out))
        except CalledProcessError:
            hookenv.log('Unable to determine if CephFS is enabled', 'ERROR')
            return False
