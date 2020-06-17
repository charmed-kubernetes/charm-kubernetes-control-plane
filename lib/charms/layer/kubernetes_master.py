import json
import socket
from pathlib import Path
import ipaddress
from itertools import islice
from subprocess import check_output, CalledProcessError, TimeoutExpired

from charmhelpers.core import hookenv
from charmhelpers.core.templating import render
from charmhelpers.core import unitdata
from charmhelpers.fetch import apt_install
from charms.reactive import endpoint_from_flag, is_flag_set

from charms.layer import kubernetes_common


STANDARD_API_PORT = 6443
CEPH_CONF_DIR = Path('/etc/ceph')
CEPH_CONF = CEPH_CONF_DIR / 'ceph.conf'
CEPH_KEYRING = CEPH_CONF_DIR / 'ceph.client.admin.keyring'

db = unitdata.kv()


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
    In 1.19+, file-based authentication was deprecated in favor of cert
    auth. Write out generic files that inform the user of this.
    """
    csv_file = Path(auth_file)
    csv_file.parent.mkdir(exist_ok=True)
    with csv_file.open('w') as f:
        f.write('# File-based authentication was deprecated in 1.19\n')


try:
    ipaddress.IPv4Network.subnet_of
except AttributeError:
    # Returns True if a is subnet of b
    # This method is copied from cpython as it is available only from
    # python 3.7
    # https://github.com/python/cpython/blob/3.7/Lib/ipaddress.py#L1000
    def _is_subnet_of(a, b):
        try:
            # Always false if one is v4 and the other is v6.
            if a._version != b._version:
                raise TypeError("{} and {} are not of the same version".format(
                    a, b))
            return (b.network_address <= a.network_address and
                    b.broadcast_address >= a.broadcast_address)
        except AttributeError:
            raise TypeError("Unable to test subnet containment "
                            "between {} and {}".format(a, b))
    ipaddress.IPv4Network.subnet_of = _is_subnet_of
    ipaddress.IPv6Network.subnet_of = _is_subnet_of


def is_service_cidr_expansion():
    service_cidr_from_db = db.get('kubernetes-master.service-cidr')
    service_cidr_from_config = hookenv.config('service-cidr')
    if not service_cidr_from_db:
        return False

    # Do not consider as expansion if both old and new service cidr are same
    if service_cidr_from_db == service_cidr_from_config:
        return False

    current_networks = kubernetes_common.get_networks(service_cidr_from_db)
    new_networks = kubernetes_common.get_networks(service_cidr_from_config)
    if not all(cur.subnet_of(new) for cur, new in zip(current_networks,
                                                      new_networks)):
        hookenv.log("WARN: New k8s service cidr not superset of old one")
        return False

    return True


def service_cidr():
    ''' Return the charm's service-cidr config'''
    frozen_cidr = db.get('kubernetes-master.service-cidr')
    return frozen_cidr or hookenv.config('service-cidr')


def freeze_service_cidr():
    ''' Freeze the service CIDR. Once the apiserver has started, we can no
    longer safely change this value. '''
    frozen_service_cidr = db.get('kubernetes-master.service-cidr')
    if not frozen_service_cidr or is_service_cidr_expansion():
        db.set('kubernetes-master.service-cidr', hookenv.config(
            'service-cidr'))


def get_preferred_service_network(service_cidrs):
    '''Get the network preferred for cluster service, preferring IPv4'''
    net_ipv4 = kubernetes_common.get_ipv4_network(service_cidrs)
    net_ipv6 = kubernetes_common.get_ipv6_network(service_cidrs)
    return net_ipv4 or net_ipv6


def get_dns_ip():
    return kubernetes_common.get_service_ip('kube-dns',
                                            namespace='kube-system')


def get_deprecated_dns_ip():
    '''We previously hardcoded the dns ip. This function returns the old
    hardcoded value for use with older versions of cdk_addons.'''
    network = get_preferred_service_network(service_cidr())
    ip = next(islice(network.hosts(), 9, None))
    return ip.exploded


def get_kubernetes_service_ips():
    '''Get the IP address(es) for the kubernetes service based on the cidr.'''
    return [next(network.hosts()).exploded
            for network in kubernetes_common.get_networks(service_cidr())]


def get_ipv6_addrs():
    '''Get all global-scoped IPv6 addresses that we might bind to.'''

    try:
        output = check_output(["ip", "-6", "-br", "a", "show", "scope", "global"])
    except CalledProcessError:
        # stderr will have any details, and go to the log
        hookenv.log('Unable to determine IPv6 addresses', hookenv.ERROR)
        return []

    addrs = []
    for line in output.splitlines():
        intf, state, *intf_addrs = line.split()
        addrs.extend(str(ipaddress.ip_interface(addr).ip) for addr in intf_addrs)
    return addrs
