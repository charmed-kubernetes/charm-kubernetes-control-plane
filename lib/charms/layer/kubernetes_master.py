from charmhelpers.core import hookenv
from charms.reactive import endpoint_from_flag

from charms.layer import kubernetes_common


def get_hacluster_ip_or_hostname():
    hacluster = endpoint_from_flag('ha.connected')
    if hacluster:
        vips = hookenv.config('ha-cluster-vip').split()
        dns_record = hookenv.config('ha-cluster-dns')
        if vips:
            # each unit will pick one based on unit number
            return vips[kubernetes_common.get_unit_number() % len(vips)]
        elif dns_record:
            return dns_record

    return None


def get_api_endpoint(relation=None):
    loadbalancer = endpoint_from_flag('loadbalancer.available')
    forced_lb_ips = hookenv.config('loadbalancer-ips').split()
    hacluster_vip = get_hacluster_ip_or_hostname()

    if forced_lb_ips:
        # if the user gave us IPs for the load balancer, assume they know
        # what they are talking about and use that instead of our information.
        round_robin = kubernetes_common.get_unit_number() % len(forced_lb_ips)
        address = forced_lb_ips[round_robin]
    elif hacluster_vip:
        address = hacluster_vip
    elif loadbalancer:
        lb_addresses = loadbalancer.get_addresses_ports()
        address = lb_addresses[0].get('public-address')
    elif relation is not None:
        try:
            network_info = hookenv.network_get(relation.endpoint_name,
                                               relation.relation_id)
            address = network_info['ingress-address']
        except NotImplementedError:
            address = hookenv.unit_public_ip()
    else:
        address = hookenv.unit_public_ip()

    if loadbalancer:
        port = lb_addresses[0].get('port')
    else:
        port = 6443

    return address, port
