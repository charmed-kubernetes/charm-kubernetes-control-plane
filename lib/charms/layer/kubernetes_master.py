import csv
import json
import random
import re
import socket
import string
import tempfile
from base64 import b64decode, b64encode
from pathlib import Path
import ipaddress
from subprocess import check_output, CalledProcessError, TimeoutExpired
from yaml import safe_load

from charmhelpers.core import hookenv
from charmhelpers.core.templating import render
from charmhelpers.core import unitdata
from charmhelpers.fetch import apt_install
from charms.reactive import endpoint_from_flag, is_flag_set
from charms.layer import kubernetes_common


AUTH_BACKUP_EXT = "pre-secrets"
AUTH_BASIC_FILE = "/root/cdk/basic_auth.csv"
AUTH_SECRET_NS = "kube-system"
AUTH_SECRET_TYPE = "juju.is/token-auth"
AUTH_TOKENS_FILE = "/root/cdk/known_tokens.csv"
STANDARD_API_PORT = 6443
CEPH_CONF_DIR = Path("/etc/ceph")
CEPH_CONF = CEPH_CONF_DIR / "ceph.conf"
CEPH_KEYRING = CEPH_CONF_DIR / "ceph.client.admin.keyring"

db = unitdata.kv()


def get_external_lb_endpoints():
    """
    Return a list of any external API load-balancer endpoints that have
    been manually configured.
    """
    ha_connected = is_flag_set("ha.connected")
    forced_lb_ips = hookenv.config("loadbalancer-ips").split()
    vips = hookenv.config("ha-cluster-vip").split()
    dns_record = hookenv.config("ha-cluster-dns")
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
    loadbalancer = endpoint_from_flag("loadbalancer.available")

    if external_lb_endpoints:
        return external_lb_endpoints
    elif loadbalancer:
        lb_addresses = loadbalancer.get_addresses_ports()
        return [(host.get("public-address"), host.get("port")) for host in lb_addresses]
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
        ingress_address = hookenv.ingress_address(
            relation.relation_id, hookenv.local_unit()
        )
        return (ingress_address, STANDARD_API_PORT)
    else:
        return (hookenv.unit_public_ip(), STANDARD_API_PORT)


def install_ceph_common():
    """Install ceph-common tools.

    :return: None
    """
    ceph_admin = endpoint_from_flag("ceph-storage.available")

    ceph_context = {
        "mon_hosts": ceph_admin.mon_hosts(),
        "fsid": ceph_admin.fsid(),
        "auth_supported": ceph_admin.auth(),
        "use_syslog": "true",
        "ceph_public_network": "",
        "ceph_cluster_network": "",
        "loglevel": 1,
        "hostname": socket.gethostname(),
    }
    # Install the ceph common utilities.
    apt_install(["ceph-common"], fatal=True)

    CEPH_CONF_DIR.mkdir(exist_ok=True, parents=True)
    # Render the ceph configuration from the ceph conf template.
    render("ceph.conf", str(CEPH_CONF), ceph_context)

    # The key can rotate independently of other ceph config, so validate it.
    try:
        with open(str(CEPH_KEYRING), "w") as key_file:
            key_file.write("[client.admin]\n\tkey = {}\n".format(ceph_admin.key()))
    except IOError as err:
        hookenv.log("IOError writing admin.keyring: {}".format(err))


def query_cephfs_enabled():
    install_ceph_common()
    try:
        out = check_output(
            ["ceph", "mds", "versions", "-c", str(CEPH_CONF)], timeout=60
        )
        return bool(json.loads(out.decode()))
    except CalledProcessError:
        hookenv.log("Unable to determine if CephFS is enabled", "ERROR")
        return False
    except TimeoutExpired:
        hookenv.log("Timeout attempting to determine if CephFS is enabled", "ERROR")
        return False


def get_cephfs_fsname():
    install_ceph_common()
    try:
        data = json.loads(check_output(["ceph", "fs", "ls", "-f", "json"], timeout=60))
    except TimeoutExpired:
        hookenv.log("Timeout attempting to determine fsname", "ERROR")
        return None
    for fs in data:
        if "ceph-fs_data" in fs["data_pools"]:
            return fs["name"]


def deprecate_auth_file(auth_file):
    """
    In 1.19+, file-based authentication was deprecated in favor of webhook
    auth. Write out generic files that inform the user of this.
    """
    csv_file = Path(auth_file)
    csv_file.parent.mkdir(exist_ok=True)

    csv_backup = Path("{}.{}".format(csv_file, AUTH_BACKUP_EXT))
    if csv_file.exists() and not csv_backup.exists():
        csv_file.rename(csv_backup)
    with csv_file.open("w") as f:
        f.write("# File-based authentication was removed in Charmed Kubernetes 1.19\n")


def migrate_auth_file(filename):
    """Create secrets or known tokens depending on what file is being migrated."""
    with open(str(filename), "r") as f:
        rows = list(csv.reader(f))

    for row in rows:
        try:
            if row[0].startswith("#"):
                continue
            else:
                if filename == AUTH_BASIC_FILE:
                    create_known_token(*row)
                elif filename == AUTH_TOKENS_FILE:
                    create_secret(*row)
                else:
                    # log and return if we don't recognize the auth file
                    hookenv.log("Unknown auth file: {}".format(filename))
                    return False
        except IndexError:
            pass
    deprecate_auth_file(filename)
    return True


def generate_rfc1123(length=10):
    """Generate a random string compliant with RFC 1123.

    https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-subdomain-names

    param: length - the length of the string to generate
    """
    length = 253 if length > 253 else length
    valid_chars = string.ascii_lowercase + string.digits
    rand_str = "".join(random.SystemRandom().choice(valid_chars) for _ in range(length))
    return rand_str


def token_generator(length=32):
    """Generate a random token for use in account tokens.

    param: length - the length of the token to generate
    """
    alpha = string.ascii_letters + string.digits
    token = "".join(random.SystemRandom().choice(alpha) for _ in range(length))
    return token


def create_known_token(token, username, user, groups=None):
    known_tokens = Path(AUTH_TOKENS_FILE)
    known_tokens.parent.mkdir(exist_ok=True)
    csv_fields = ["token", "username", "user", "groups"]

    try:
        with known_tokens.open("r") as f:
            tokens_by_user = {r["user"]: r for r in csv.DictReader(f, csv_fields)}
    except FileNotFoundError:
        tokens_by_user = {}
    tokens_by_username = {r["username"]: r for r in tokens_by_user.values()}

    if user in tokens_by_user:
        record = tokens_by_user[user]
    elif username in tokens_by_username:
        record = tokens_by_username[username]
    else:
        record = tokens_by_user[user] = {}
    record.update(
        {
            "token": token,
            "username": username,
            "user": user,
            "groups": groups,
        }
    )

    if not record["groups"]:
        del record["groups"]

    with known_tokens.open("w") as f:
        csv.DictWriter(f, csv_fields, lineterminator="\n").writerows(
            tokens_by_user.values()
        )


def create_secret(token, username, user, groups=None):
    secrets = get_secret_names()
    if username in secrets:
        # Use existing secret ID if one exists for our username
        secret_id = secrets[username]
    else:
        # secret IDs must be unique and rfc1123 compliant
        sani_name = re.sub("[^0-9a-z.-]+", "-", user.lower())
        secret_id = "auth-{}-{}".format(sani_name, generate_rfc1123(10))

    # The authenticator expects tokens to be in the form user::token
    token_delim = "::"
    if token_delim not in token:
        token = "{}::{}".format(user, token)

    context = {
        "type": AUTH_SECRET_TYPE,
        "secret_name": secret_id,
        "secret_namespace": AUTH_SECRET_NS,
        "user": b64encode(user.encode("UTF-8")).decode("utf-8"),
        "username": b64encode(username.encode("UTF-8")).decode("utf-8"),
        "password": b64encode(token.encode("UTF-8")).decode("utf-8"),
        "groups": b64encode(groups.encode("UTF-8")).decode("utf-8") if groups else "",
    }
    with tempfile.NamedTemporaryFile() as tmp_manifest:
        render(
            "cdk.master.auth-webhook-secret.yaml", tmp_manifest.name, context=context
        )

        if kubernetes_common.kubectl_manifest("apply", tmp_manifest.name):
            hookenv.log("Created secret for {}".format(username))
            return True
        else:
            hookenv.log("WARN: Unable to create secret for {}".format(username))
            return False


def delete_secret(secret_id):
    """Delete a given secret id."""
    # If this fails, it's most likely because we're trying to delete a secret
    # that doesn't exist. Let the caller decide if failure is a problem.
    return kubernetes_common.kubectl_success(
        "delete", "secret", "-n", AUTH_SECRET_NS, secret_id
    )


def get_csv_password(csv_fname, user):
    """Get the password for the given user within the csv file provided."""
    root_cdk = "/root/cdk"
    tokens_fname = Path(root_cdk) / csv_fname
    if not tokens_fname.is_file():
        return None
    with tokens_fname.open("r") as stream:
        for line in stream:
            record = line.split(",")
            try:
                if record[1] == user:
                    return record[0]
            except IndexError:
                # probably a blank line or comment; move on
                continue
    return None


def get_secret_names():
    """Return a dict of 'username: secret_id' for Charmed Kubernetes users."""
    try:
        output = kubernetes_common.kubectl(
            "get",
            "secrets",
            "-n",
            AUTH_SECRET_NS,
            "--field-selector",
            "type={}".format(AUTH_SECRET_TYPE),
            "-o",
            "json",
        ).decode("UTF-8")
    except (CalledProcessError, FileNotFoundError):
        # The api server may not be up, or we may be trying to run kubelet before
        # the snap is installed. Send back an empty dict.
        hookenv.log("Unable to get existing secrets", level=hookenv.WARNING)
        return {}

    secrets = json.loads(output)
    secret_names = {}
    if "items" in secrets:
        for secret in secrets["items"]:
            try:
                secret_id = secret["metadata"]["name"]
                username_b64 = secret["data"]["username"].encode("UTF-8")
            except (KeyError, TypeError):
                # CK secrets will have populated 'data', but not all secrets do
                continue
            secret_names[b64decode(username_b64).decode("UTF-8")] = secret_id
    return secret_names


def get_secret_password(username):
    """Get the password for the given user from the secret that CK created."""
    try:
        output = kubernetes_common.kubectl(
            "get",
            "secrets",
            "-n",
            AUTH_SECRET_NS,
            "--field-selector",
            "type={}".format(AUTH_SECRET_TYPE),
            "-o",
            "json",
        ).decode("UTF-8")
    except CalledProcessError:
        # NB: apiserver probably isn't up. This can happen on boostrap or upgrade
        # while trying to build kubeconfig files. If we need the 'admin' token during
        # this time, pull it directly out of the kubeconfig file if possible.
        token = None
        if username == "admin":
            admin_kubeconfig = Path("/root/.kube/config")
            if admin_kubeconfig.exists():
                with admin_kubeconfig.open("r") as f:
                    data = safe_load(f)
                    try:
                        token = data["users"][0]["user"]["token"]
                    except (KeyError, ValueError):
                        pass
        return token
    except FileNotFoundError:
        # New deployments may ask for a token before the kubectl snap is installed.
        # Give them nothing!
        return None

    secrets = json.loads(output)
    if "items" in secrets:
        for secret in secrets["items"]:
            try:
                data_b64 = secret["data"]
                password_b64 = data_b64["password"].encode("UTF-8")
                username_b64 = data_b64["username"].encode("UTF-8")
            except (KeyError, TypeError):
                # CK authn secrets will have populated 'data', but not all secrets do
                continue

            password = b64decode(password_b64).decode("UTF-8")
            secret_user = b64decode(username_b64).decode("UTF-8")
            if username == secret_user:
                return password
    return None


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
                raise TypeError("{} and {} are not of the same version".format(a, b))
            return (
                b.network_address <= a.network_address
                and b.broadcast_address >= a.broadcast_address
            )
        except AttributeError:
            raise TypeError(
                "Unable to test subnet containment " "between {} and {}".format(a, b)
            )

    ipaddress.IPv4Network.subnet_of = _is_subnet_of
    ipaddress.IPv6Network.subnet_of = _is_subnet_of


def is_service_cidr_expansion():
    service_cidr_from_db = db.get("kubernetes-master.service-cidr")
    service_cidr_from_config = hookenv.config("service-cidr")
    if not service_cidr_from_db:
        return False

    # Do not consider as expansion if both old and new service cidr are same
    if service_cidr_from_db == service_cidr_from_config:
        return False

    current_networks = kubernetes_common.get_networks(service_cidr_from_db)
    new_networks = kubernetes_common.get_networks(service_cidr_from_config)
    if len(current_networks) != len(new_networks) or not all(
        cur.subnet_of(new) for cur, new in zip(current_networks, new_networks)
    ):
        hookenv.log("WARN: New k8s service cidr not superset of old one")
        return False

    return True


def service_cidr():
    """Return the charm's service-cidr config"""
    frozen_cidr = db.get("kubernetes-master.service-cidr")
    return frozen_cidr or hookenv.config("service-cidr")


def freeze_service_cidr():
    """Freeze the service CIDR. Once the apiserver has started, we can no
    longer safely change this value."""
    frozen_service_cidr = db.get("kubernetes-master.service-cidr")
    if not frozen_service_cidr or is_service_cidr_expansion():
        db.set("kubernetes-master.service-cidr", hookenv.config("service-cidr"))


def get_preferred_service_network(service_cidrs):
    """Get the network preferred for cluster service, preferring IPv4"""
    net_ipv4 = kubernetes_common.get_ipv4_network(service_cidrs)
    net_ipv6 = kubernetes_common.get_ipv6_network(service_cidrs)
    return net_ipv4 or net_ipv6


def get_dns_ip():
    return kubernetes_common.get_service_ip("kube-dns", namespace="kube-system")


def get_kubernetes_service_ips():
    """Get the IP address(es) for the kubernetes service based on the cidr."""
    return [
        next(network.hosts()).exploded
        for network in kubernetes_common.get_networks(service_cidr())
    ]


def get_snap_revs(snaps):
    """Get a dict of snap revisions for a given list of snaps."""
    channel = hookenv.config("channel")
    rev_info = {}
    for s in sorted(snaps):
        try:
            # valid info should looke like:
            #  ...
            #  channels:
            #    latest/stable:    1.18.8         2020-08-27 (1595) 22MB classic
            #    latest/candidate: 1.18.8         2020-08-27 (1595) 22MB classic
            #  ...
            info = check_output(["snap", "info", s]).decode("utf8", errors="ignore")
        except CalledProcessError:
            # If 'snap info' fails for whatever reason, just empty the info
            info = ""
        snap_rev = None
        yaml_data = safe_load(info)
        if yaml_data and "channels" in yaml_data:
            try:
                # valid data should look like:
                #  ['1.18.8', '2020-08-27', '(1604)', '21MB', 'classic']
                d = yaml_data["channels"][channel].split()
                snap_rev = d[2].strip("()")
            except (KeyError, IndexError):
                hookenv.log(
                    "Could not determine revision for snap: {}".format(s),
                    level=hookenv.WARNING,
                )
        rev_info[s] = snap_rev
    return rev_info
