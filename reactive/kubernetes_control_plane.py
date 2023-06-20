#!/usr/local/sbin/charm-env python3

# Copyright 2015 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import json
import os
import re
import socket
import traceback
import yaml

from itertools import filterfalse
from shutil import move, copyfile
from pathlib import Path
from subprocess import check_call, call
from subprocess import check_output
from subprocess import CalledProcessError
from typing import Mapping, Optional
from urllib.request import Request, urlopen

import charms.coordinator
from charms.layer import snap
from charms.leadership import leader_get, leader_set
from charms.reactive import hook
from charms.reactive import remove_state, clear_flag
from charms.reactive import get_flags, set_state, set_flag
from charms.reactive import is_state, is_flag_set, get_unset_flags
from charms.reactive import endpoint_from_flag, endpoint_from_name
from charms.reactive import when, when_any, when_not, when_none
from charms.reactive import register_trigger
from charms.reactive import data_changed, any_file_changed

from charms.layer import tls_client
from charms.layer import vaultlocker
from charms.layer import vault_kv

from charmhelpers.core import hookenv
from charmhelpers.core import host
from charmhelpers.core import unitdata
from charmhelpers.core.host import restart_on_change
from charmhelpers.core.host import (
    service_pause,
    service_resume,
    service_running,
    service_stop,
)
from charmhelpers.core.templating import render
from charmhelpers.contrib.charmsupport import nrpe
from charmhelpers.contrib.storage.linux.ceph import CephBrokerRq

from charms.layer import kubernetes_control_plane
from charms.layer import kubernetes_common

from charms.layer.kubernetes_common import kubeclientconfig_path
from charms.layer.kubernetes_common import migrate_resource_checksums
from charms.layer.kubernetes_common import check_resources_for_upgrade_needed
from charms.layer.kubernetes_common import (
    calculate_and_store_resource_checksums,
)  # noqa
from charms.layer.kubernetes_common import arch
from charms.layer.kubernetes_common import service_restart
from charms.layer.kubernetes_common import get_ingress_address
from charms.layer.kubernetes_common import get_ingress_address6
from charms.layer.kubernetes_common import create_kubeconfig
from charms.layer.kubernetes_common import get_service_ip
from charms.layer.kubernetes_common import configure_kubernetes_service
from charms.layer.kubernetes_common import cloud_config_path
from charms.layer.kubernetes_common import encryption_config_path
from charms.layer.kubernetes_common import write_gcp_snap_config
from charms.layer.kubernetes_common import generate_openstack_cloud_config
from charms.layer.kubernetes_common import write_azure_snap_config
from charms.layer.kubernetes_common import configure_kube_proxy
from charms.layer.kubernetes_common import kubeproxyconfig_path
from charms.layer.kubernetes_common import get_version
from charms.layer.kubernetes_common import retry
from charms.layer.kubernetes_common import ca_crt_path
from charms.layer.kubernetes_common import server_crt_path
from charms.layer.kubernetes_common import server_key_path
from charms.layer.kubernetes_common import client_crt_path
from charms.layer.kubernetes_common import client_key_path
from charms.layer.kubernetes_common import kubectl, kubectl_manifest, kubectl_success
from charms.layer.kubernetes_common import _get_vmware_uuid
from charms.layer.kubernetes_common import get_node_name
from charms.layer.kubernetes_common import get_sandbox_image_uri
from charms.layer.kubernetes_common import kubelet_kubeconfig_path
from charms.layer.kubernetes_common import add_systemd_restart_always
from charms.layer.kubernetes_common import cni_config_exists

from charms.layer.kubernetes_node_base import LabelMaker

from charms.layer.nagios import install_nagios_plugin_from_file
from charms.layer.nagios import remove_nagios_plugin


# Override the default nagios shortname regex to allow periods, which we
# need because our bin names contain them (e.g. 'snap.foo.daemon'). The
# default regex in charmhelpers doesn't allow periods, but nagios itself does.
nrpe.Check.shortname_re = r"[\.A-Za-z0-9-_]+$"

snap_resources = [
    "kubectl",
    "kube-apiserver",
    "kube-controller-manager",
    "kube-scheduler",
    "cdk-addons",
    "kube-proxy",
    "kubelet",
]

control_plane_services = [
    "kube-apiserver",
    "kube-controller-manager",
    "kube-scheduler",
    "kube-proxy",
    "kubelet",
]

cohort_snaps = snap_resources


os.environ["PATH"] += os.pathsep + os.path.join(os.sep, "snap", "bin")
db = unitdata.kv()
checksum_prefix = "kubernetes-master.resource-checksums."
configure_prefix = "kubernetes-master.prev_args."
keystone_root = "/root/cdk/keystone"
keystone_policy_path = os.path.join(keystone_root, "keystone-policy.yaml")
kubecontrollermanagerconfig_path = "/root/cdk/kubecontrollermanagerconfig"
kubeschedulerconfig_path = "/root/cdk/kubeschedulerconfig"
cdk_addons_kubectl_config_path = "/root/cdk/cdk_addons_kubectl_config"
kubernetes_logs = "/var/log/kubernetes/"
aws_iam_webhook = "/root/cdk/aws-iam-webhook.yaml"
auth_webhook_root = "/root/cdk/auth-webhook"
auth_webhook_conf = os.path.join(auth_webhook_root, "auth-webhook-conf.yaml")
auth_webhook_exe = os.path.join(auth_webhook_root, "auth-webhook.py")
auth_webhook_svc_name = "cdk.master.auth-webhook"
auth_webhook_svc = "/etc/systemd/system/{}.service".format(auth_webhook_svc_name)
tls_ciphers_intermediate = [
    # https://wiki.mozilla.org/Security/Server_Side_TLS
    # https://ssl-config.mozilla.org/#server=go&config=intermediate
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
]


register_trigger(
    when="endpoint.aws.ready",
    set_flag="kubernetes-control-plane.aws.changed",  # when set
)
register_trigger(
    when_not="endpoint.aws.ready",  # when cleared
    set_flag="kubernetes-control-plane.aws.changed",
)
register_trigger(
    when="endpoint.azure.ready",
    set_flag="kubernetes-control-plane.azure.changed",  # when set
)
register_trigger(
    when_not="endpoint.azure.ready",  # when cleared
    set_flag="kubernetes-control-plane.azure.changed",
)
register_trigger(
    when="endpoint.gcp.ready",
    set_flag="kubernetes-control-plane.gcp.changed",  # when set
)
register_trigger(
    when_not="endpoint.gcp.ready",  # when cleared
    set_flag="kubernetes-control-plane.gcp.changed",
)
register_trigger(
    when="keystone-credentials.available", set_flag="cdk-addons.reconfigure"
)
register_trigger(
    when_not="keystone-credentials.available", set_flag="cdk-addons.reconfigure"
)
register_trigger(
    when="kubernetes-control-plane.aws.changed", set_flag="cdk-addons.reconfigure"
)
register_trigger(
    when="kubernetes-control-plane.azure.changed", set_flag="cdk-addons.reconfigure"
)
register_trigger(
    when="kubernetes-control-plane.gcp.changed", set_flag="cdk-addons.reconfigure"
)
register_trigger(
    when="kubernetes-control-plane.openstack.changed", set_flag="cdk-addons.reconfigure"
)
register_trigger(
    when_not="cni.available", clear_flag="kubernetes-control-plane.components.started"
)
register_trigger(
    when="kube-control.requests.changed", clear_flag="authentication.setup"
)
register_trigger(
    when_not="kubernetes-control-plane.apiserver.configured",
    clear_flag="kubernetes-control-plane.apiserver.running",
)
register_trigger(
    when="config.changed.image-registry",
    clear_flag="kubernetes-control-plane.kubelet.configured",
)
register_trigger(
    when="config.changed.image-registry",
    clear_flag="kubernetes-control-plane.sent-registry",
)
register_trigger(
    when="config.changed.default-cni",
    clear_flag="kubernetes-control-plane.default-cni.configured",
)
register_trigger(
    when_not="ceph-client.connected",
    clear_flag="kubernetes-control-plane.ceph.pools.created",
)
register_trigger(
    when_not="ceph-client.connected",
    clear_flag="kubernetes-control-plane.ceph.permissions.requested",
)
register_trigger(
    when="ceph-client.available",
    clear_flag="kubernetes-control-plane.apiserver.configured",
)
register_trigger(
    when_not="ceph-client.available",
    clear_flag="kubernetes-control-plane.apiserver.configured",
)
# when CNI becomes available, reconfigure k8s services with the cluster-cidr
register_trigger(
    when="cni.available", clear_flag="kubernetes-control-plane.components.started"
)
register_trigger(
    when="config.changed.proxy-extra-config",
    clear_flag="kubernetes-control-plane.components.started",
)


def set_upgrade_needed(forced=False):
    set_state("kubernetes-control-plane.upgrade-needed")
    config = hookenv.config()
    previous_channel = config.previous("channel")
    require_manual = config.get("require-manual-upgrade")
    hookenv.log("set upgrade needed")
    if previous_channel is None or not require_manual or forced:
        hookenv.log("forcing upgrade")
        set_state("kubernetes-control-plane.upgrade-specified")


@when("config.changed.channel")
def channel_changed():
    set_upgrade_needed()


def maybe_install_kubelet():
    if not snap.is_installed("kubelet"):
        channel = hookenv.config("channel")
        hookenv.status_set("maintenance", "Installing kubelet snap")
        snap.install("kubelet", channel=channel, classic=True)
        calculate_and_store_resource_checksums(checksum_prefix, snap_resources)


def maybe_install_kube_proxy():
    if not snap.is_installed("kube-proxy"):
        channel = hookenv.config("channel")
        hookenv.status_set("maintenance", "Installing kube-proxy snap")
        snap.install("kube-proxy", channel=channel, classic=True)
        calculate_and_store_resource_checksums(checksum_prefix, snap_resources)


@hook("install")
def fresh_install():
    # fresh installs should always send the unique cluster tag to cdk-addons
    set_state("kubernetes-control-plane.cdk-addons.unique-cluster-tag")


@hook("upgrade-charm")
def check_for_upgrade_needed():
    """An upgrade charm event was triggered by Juju, react to that here."""
    hookenv.status_set("maintenance", "Checking resources")
    is_leader = is_state("leadership.is_leader")

    # migrate to inclusive flags
    old, new = "kubernetes-master", "kubernetes-control-plane"  # wokeignore:rule=master
    for flag in get_flags():
        if flag.startswith(old):
            new_flag = flag.replace(old, new, 1)
            clear_flag(flag)
            set_flag(new_flag)

    # migrate to new flags
    if is_state("kubernetes-control-plane.restarted-for-cloud"):
        remove_state("kubernetes-control-plane.restarted-for-cloud")
        set_state("kubernetes-control-plane.cloud.ready")
    if is_state("kubernetes-control-plane.cloud-request-sent"):
        # minor change, just for consistency
        remove_state("kubernetes-control-plane.cloud-request-sent")
        set_state("kubernetes-control-plane.cloud.request-sent")
    if is_flag_set("kubernetes-control-plane.snaps.installed"):
        # consistent with layer-kubernetes-node-base
        remove_state("kubernetes-control-plane.snaps.installed")
        set_state("kubernetes-node.snaps.installed")

    # ceph-storage.configured flag no longer exists
    remove_state("ceph-storage.configured")

    # kubernetes-control-plane.ceph.configured flag no longer exists
    remove_state("kubernetes-control-plane.ceph.configured")

    maybe_install_kubelet()
    maybe_install_kube_proxy()
    update_certificates()
    maybe_heal_vault_kv()
    switch_auth_mode(forced=True)

    # File-based auth is gone in 1.19; ensure any entries in basic_auth.csv are
    # added to known_tokens.csv, and any known_tokens entries are created as secrets.
    if not is_flag_set("kubernetes-control-plane.basic-auth.migrated"):
        if kubernetes_control_plane.migrate_auth_file(
            kubernetes_control_plane.AUTH_BASIC_FILE
        ):
            set_flag("kubernetes-control-plane.basic-auth.migrated")
        else:
            hookenv.log(
                "Unable to migrate {} to {}".format(
                    kubernetes_control_plane.AUTH_BASIC_FILE,
                    kubernetes_control_plane.AUTH_TOKENS_FILE,
                )
            )
    if not is_flag_set("kubernetes-control-plane.token-auth.migrated"):
        register_auth_webhook()
        add_rbac_roles()
        if kubernetes_control_plane.migrate_auth_file(
            kubernetes_control_plane.AUTH_TOKENS_FILE
        ):
            set_flag("kubernetes-control-plane.token-auth.migrated")
        else:
            hookenv.log(
                "Unable to migrate {} to Kubernetes secrets".format(
                    kubernetes_control_plane.AUTH_TOKENS_FILE
                )
            )
    set_state("reconfigure.authentication.setup")
    remove_state("authentication.setup")

    if not db.get("snap.resources.fingerprint.initialised"):
        # We are here on an upgrade from non-rolling control plane
        # Since this upgrade might also include resource updates eg
        # juju upgrade-charm kubernetes-control-plane --resource kube-any=my.snap
        # we take no risk and forcibly upgrade the snaps.
        # Forcibly means we do not prompt the user to call the upgrade action.
        set_upgrade_needed(forced=True)

    migrate_resource_checksums(checksum_prefix, snap_resources)
    if check_resources_for_upgrade_needed(checksum_prefix, snap_resources):
        set_upgrade_needed()

    # Set the auto storage backend to etcd2.
    auto_storage_backend = leader_get("auto_storage_backend")
    if not auto_storage_backend and is_leader:
        leader_set(auto_storage_backend="etcd2")

    if is_leader and not leader_get("auto_dns_provider"):
        leader_set(auto_dns_provider="core-dns")

    if is_flag_set("nrpe-external-master.available"):
        update_nrpe_config()

    remove_state("kubernetes-control-plane.system-monitoring-rbac-role.applied")
    remove_state("kubernetes-control-plane.kubelet.configured")
    remove_state("kubernetes-control-plane.default-cni.configured")
    remove_state("kubernetes-control-plane.sent-registry")
    remove_state("kubernetes-control-plane.ceph.permissions.requested")

    # Remove services from hacluster and leave to systemd while
    # hacluster is not ready to accept order and colocation constraints
    if is_flag_set("ha.connected"):
        hacluster = endpoint_from_flag("ha.connected")
        for service in control_plane_services:
            daemon = "snap.{}.daemon".format(service)
            hacluster.remove_systemd_service(service, daemon)


@hook("pre-series-upgrade")
def pre_series_upgrade():
    """Stop the kubernetes control plane services"""
    for service in control_plane_services:
        service_pause("snap.%s.daemon" % service)


@hook("post-series-upgrade")
def post_series_upgrade():
    for service in control_plane_services:
        service_resume("snap.%s.daemon" % service)
    # set ourselves up to restart
    remove_state("kubernetes-control-plane.components.started")


@hook("leader-elected")
def leader_elected():
    clear_flag("authentication.setup")


def add_rbac_roles():
    """Update the known_tokens file with proper groups.

    DEPRECATED: Once known_tokens are migrated, group data will be stored in K8s
    secrets. Do not use this function after migrating to authn with secrets.
    """
    if is_flag_set("kubernetes-control-plane.token-auth.migrated"):
        hookenv.log("Known tokens have migrated to secrets. Skipping group changes")
        return
    tokens_fname = "/root/cdk/known_tokens.csv"
    tokens_backup_fname = "/root/cdk/known_tokens.csv.backup"
    move(tokens_fname, tokens_backup_fname)
    with open(tokens_fname, "w") as ftokens:
        with open(tokens_backup_fname, "r") as stream:
            for line in stream:
                if line.startswith("#"):
                    continue
                record = line.strip().split(",")
                try:
                    # valid line looks like: token,username,user,groups
                    if record[2] == "admin" and len(record) == 3:
                        towrite = '{0},{1},{2},"{3}"\n'.format(
                            record[0], record[1], record[2], "system:masters"
                        )
                        ftokens.write(towrite)
                        continue
                    if record[2] == "kube_proxy":
                        towrite = "{0},{1},{2}\n".format(
                            record[0], "system:kube-proxy", "kube-proxy"
                        )
                        ftokens.write(towrite)
                        continue
                    if record[2] == "kube_controller_manager":
                        towrite = "{0},{1},{2}\n".format(
                            record[0],
                            "system:kube-controller-manager",
                            "kube-controller-manager",
                        )
                        ftokens.write(towrite)
                        continue
                    if record[2] == "kubelet" and record[1] == "kubelet":
                        continue
                except IndexError:
                    msg = "Skipping invalid line from {}: {}".format(
                        tokens_backup_fname, line
                    )
                    hookenv.log(msg, level=hookenv.DEBUG)
                    continue
                else:
                    ftokens.write("{}".format(line))


@when("kubernetes-control-plane.upgrade-specified")
def do_upgrade():
    install_snaps()
    remove_state("kubernetes-control-plane.upgrade-needed")
    remove_state("kubernetes-control-plane.upgrade-specified")


def install_snaps():
    channel = hookenv.config("channel")
    hookenv.status_set("maintenance", "Installing core snap")
    snap.install("core")
    hookenv.status_set("maintenance", "Installing kubectl snap")
    snap.install("kubectl", channel=channel, classic=True)
    hookenv.status_set("maintenance", "Installing kube-apiserver snap")
    snap.install("kube-apiserver", channel=channel)
    hookenv.status_set("maintenance", "Installing kube-controller-manager snap")
    snap.install("kube-controller-manager", channel=channel)
    hookenv.status_set("maintenance", "Installing kube-scheduler snap")
    snap.install("kube-scheduler", channel=channel)
    hookenv.status_set("maintenance", "Installing cdk-addons snap")
    snap.install("cdk-addons", channel=channel)
    hookenv.status_set("maintenance", "Installing kubelet snap")
    snap.install("kubelet", channel=channel, classic=True)
    hookenv.status_set("maintenance", "Installing kube-proxy snap")
    snap.install("kube-proxy", channel=channel, classic=True)
    calculate_and_store_resource_checksums(checksum_prefix, snap_resources)
    db.set("snap.resources.fingerprint.initialised", True)
    set_state("kubernetes-node.snaps.installed")
    remove_state("kubernetes-control-plane.components.started")


@when("kubernetes-node.snaps.installed", "leadership.is_leader")
@when_not("leadership.set.cohort_keys")
def create_or_update_cohort_keys():
    cohort_keys = {}
    for snapname in cohort_snaps:
        try:
            cohort_key = snap.create_cohort_snapshot(snapname)
        except CalledProcessError:
            # Snap store outages prevent keys from being created; log it
            # and retry later. LP:1956608
            hookenv.log(
                "Failed to create cohort for {}; will retry".format(snapname),
                level=hookenv.INFO,
            )
            return
        cohort_keys[snapname] = cohort_key
    leader_set(cohort_keys=json.dumps(cohort_keys))
    hookenv.log("Snap cohort keys have been created.", level=hookenv.INFO)

    # Prime revision info so we can detect changes later
    cohort_revs = kubernetes_control_plane.get_snap_revs(cohort_snaps)
    data_changed("leader-cohort-revs", cohort_revs)
    hookenv.log(
        "Tracking cohort revisions: {}".format(cohort_revs), level=hookenv.DEBUG
    )


@when(
    "kubernetes-node.snaps.installed",
    "leadership.is_leader",
    "leadership.set.cohort_keys",
)
def check_cohort_updates():
    cohort_revs = kubernetes_control_plane.get_snap_revs(cohort_snaps)
    if cohort_revs and data_changed("leader-cohort-revs", cohort_revs):
        leader_set(cohort_keys=None)
        hookenv.log("Snap cohort revisions have changed.", level=hookenv.INFO)


@when("kubernetes-node.snaps.installed", "leadership.set.cohort_keys")
@when_none("coordinator.granted.cohort", "coordinator.requested.cohort")
def safely_join_cohort():
    """Coordinate the rollout of snap refreshes.

    When cohort keys change, grab a lock so that only 1 unit in the
    application joins the new cohort at a time. This allows us to roll out
    snap refreshes without risking all units going down at once.
    """
    cohort_keys = leader_get("cohort_keys")
    # NB: initial data-changed is always true
    if data_changed("leader-cohorts", cohort_keys):
        clear_flag("kubernetes-control-plane.cohorts.joined")
        clear_flag("kubernetes-control-plane.cohorts.sent")
        charms.coordinator.acquire("cohort")


@when(
    "kubernetes-node.snaps.installed",
    "leadership.set.cohort_keys",
    "coordinator.granted.cohort",
)
@when_not("kubernetes-control-plane.cohorts.joined")
def join_or_update_cohorts():
    """Join or update a cohort snapshot.

    All units of this application (leader and followers) need to refresh their
    installed snaps to the current cohort snapshot.
    """
    cohort_keys = json.loads(leader_get("cohort_keys"))
    for snapname in cohort_snaps:
        cohort_key = cohort_keys[snapname]
        if snap.is_installed(snapname):  # we also manage workers' cohorts
            hookenv.status_set("maintenance", "Joining snap cohort.")
            snap.join_cohort_snapshot(snapname, cohort_key)
    set_flag("kubernetes-control-plane.cohorts.joined")
    hookenv.log("{} has joined the snap cohort".format(hookenv.local_unit()))


@when(
    "kubernetes-node.snaps.installed",
    "leadership.set.cohort_keys",
    "kubernetes-control-plane.cohorts.joined",
    "kube-control.connected",
)
@when_not("kubernetes-control-plane.cohorts.sent")
def send_cohorts():
    """Send cohort information to workers.

    If we have peers, wait until all peers are updated before sending.
    Otherwise, we're a single unit k8s-cp and can fire when connected.
    """
    cohort_keys = json.loads(leader_get("cohort_keys"))
    kube_control = endpoint_from_flag("kube-control.connected")
    kube_cps = endpoint_from_flag("kube-masters.connected")  # wokeignore:rule=master

    # If we have peers, tell them we've joined the cohort. This is needed so
    # we don't tell workers about cohorts until all control planes are in-sync.
    goal_peers = len(list(hookenv.expected_peer_units()))
    if goal_peers > 0:
        if kube_cps:
            # tell peers about the cohort keys
            kube_cps.set_cohort_keys(cohort_keys)
        else:
            msg = "Waiting for {} peers before setting the cohort.".format(goal_peers)
            hookenv.log(msg, level=hookenv.DEBUG)
            return

        if is_flag_set("kube-masters.cohorts.ready"):
            # tell workers about the cohort keys
            kube_control.set_cohort_keys(cohort_keys)
            hookenv.log(
                "{} (peer) sent cohort keys to workers".format(hookenv.local_unit())
            )
        else:
            msg = "Waiting for k8s-cps to agree on cohorts."
            hookenv.log(msg, level=hookenv.DEBUG)
            return
    else:
        # tell workers about the cohort keys
        kube_control.set_cohort_keys(cohort_keys)
        hookenv.log(
            "{} (single) sent cohort keys to workers".format(hookenv.local_unit())
        )

    set_flag("kubernetes-control-plane.cohorts.sent")


@when("config.changed.client_password", "leadership.is_leader")
def password_changed():
    """Handle password change by reconfiguring authentication."""
    remove_state("authentication.setup")


@when("config.changed.storage-backend")
def storage_backend_changed():
    remove_state("kubernetes-control-plane.components.started")


@when("leadership.is_leader")
@when_not("authentication.setup")
def setup_leader_authentication():
    """
    Setup service accounts and tokens for the cluster.

    As of 1.19 charms, this will also propogate a generic basic_auth.csv, which is
    merged into known_tokens.csv, which are migrated to secrets during upgrade-charm.
    """
    basic_auth = "/root/cdk/basic_auth.csv"
    known_tokens = "/root/cdk/known_tokens.csv"
    service_key = "/root/cdk/serviceaccount.key"
    os.makedirs("/root/cdk", exist_ok=True)

    hookenv.status_set("maintenance", "Rendering authentication templates.")

    keys = [basic_auth, known_tokens, service_key]
    # Try first to fetch data from an old leadership broadcast.
    if not get_keys_from_leader(keys) or is_state("reconfigure.authentication.setup"):
        kubernetes_control_plane.deprecate_auth_file(basic_auth)
        set_flag("kubernetes-control-plane.basic-auth.migrated")

        kubernetes_control_plane.deprecate_auth_file(known_tokens)
        set_flag("kubernetes-control-plane.token-auth.migrated")

        # Generate the default service account token key
        if not os.path.isfile(service_key):
            cmd = ["openssl", "genrsa", "-out", service_key, "2048"]
            check_call(cmd)
        remove_state("reconfigure.authentication.setup")

    # Write the admin token every time we setup authn to ensure we honor a
    # configured password.
    client_pass = hookenv.config("client_password") or get_token("admin")
    setup_tokens(client_pass, "admin", "admin", "system:masters")

    create_tokens_and_sign_auth_requests()

    # send auth files to followers via leadership data
    leader_data = {}
    for f in [basic_auth, known_tokens, service_key]:
        try:
            with open(f, "r") as fp:
                leader_data[f] = fp.read()
        except FileNotFoundError:
            pass

    # this is slightly opaque, but we are sending file contents under its file
    # path as a key.
    # eg:
    # {'/root/cdk/serviceaccount.key': 'RSA:2471731...'}
    leader_set(leader_data)

    remove_state("kubernetes-control-plane.components.started")
    remove_state("kube-control.requests.changed")
    set_state("authentication.setup")


@when_not("leadership.is_leader")
def setup_non_leader_authentication():
    basic_auth = "/root/cdk/basic_auth.csv"
    known_tokens = "/root/cdk/known_tokens.csv"
    service_key = "/root/cdk/serviceaccount.key"

    # Starting with 1.19, we don't use csv auth files; handle changing secrets.
    secrets = {
        "admin": get_token("admin"),
        "kube-controller-manager": get_token("system:kube-controller-manager"),
        "kube-proxy": get_token("system:kube-proxy"),
        "kube-scheduler": get_token("system:kube-scheduler"),
    }
    if data_changed("secrets-data", secrets):
        set_flag("kubernetes-control-plane.token-auth.migrated")
        build_kubeconfig()
        remove_state("kubernetes-control-plane.components.started")

    keys = [basic_auth, known_tokens, service_key]
    # Pre-secrets, the source of truth for non-leaders is the leader.
    # Therefore we overwrite_local with whatever the leader has.
    if not get_keys_from_leader(keys, overwrite_local=True):
        # the keys were not retrieved. Non-leaders have to retry.
        return

    if any_file_changed(keys):
        remove_state("kubernetes-control-plane.components.started")

    # Clear stale creds from the kube-control relation so that the leader can
    # assume full control of them.
    kube_control = endpoint_from_flag("kube-control.connected")
    if kube_control:
        kube_control.clear_creds()

    remove_state("kube-control.requests.changed")
    set_state("authentication.setup")


def get_keys_from_leader(keys, overwrite_local=False):
    """
    Gets the broadcasted keys from the leader and stores them in
    the corresponding files.

    Args:
        keys: list of keys. Keys are actually files on the FS.

    Returns: True if all key were fetched, False if not.

    """
    # This races with other codepaths, and seems to require being created first
    # This block may be extracted later, but for now seems to work as intended
    os.makedirs("/root/cdk", exist_ok=True)

    for k in keys:
        # If the path does not exist, assume we need it
        if not os.path.exists(k) or overwrite_local:
            # Fetch data from leadership broadcast
            contents = leader_get(k)
            # Default to logging the warning and wait for leader data to be set
            if contents is None:
                hookenv.log("Missing content for file {}".format(k))
                return False
            # Write out the file and move on to the next item
            with open(k, "w+") as fp:
                fp.write(contents)
                fp.write("\n")

    return True


@when("kubernetes-node.snaps.installed")
def set_app_version():
    """Declare the application version to juju"""
    version = check_output(["kube-apiserver", "--version"])
    hookenv.application_version_set(version.split(b" v")[-1].rstrip())


@hookenv.atstart
def check_vault_pending():
    try:
        goal_state = hookenv.goal_state()
    except NotImplementedError:
        goal_state = {}
    vault_kv_goal = "vault-kv" in goal_state.get("relations", {})
    vault_kv_connected = is_state("vault-kv.connected")
    vault_kv_related = vault_kv_goal or vault_kv_connected
    vault_kv_ready = is_state("layer.vault-kv.ready")
    if vault_kv_related and not vault_kv_ready:
        set_flag("kubernetes-control-plane.vault-kv.pending")
    else:
        clear_flag("kubernetes-control-plane.vault-kv.pending")


@hookenv.atexit
def set_final_status():
    """Set the final status of the charm as we leave hook execution"""
    try:
        goal_state = hookenv.goal_state()
    except NotImplementedError:
        goal_state = {}

    if is_flag_set("upgrade.series.in-progress"):
        hookenv.status_set("blocked", "Series upgrade in progress")
        return

    if not is_flag_set("certificates.available"):
        if "certificates" in goal_state.get("relations", {}):
            hookenv.status_set("waiting", "Waiting for certificates authority.")
        else:
            hookenv.status_set("blocked", "Missing relation to certificate authority.")
        return

    if is_flag_set("kubernetes-control-plane.secure-storage.failed"):
        hookenv.status_set(
            "blocked",
            "Failed to configure encryption; "
            "secrets are unencrypted or inaccessible",
        )
        return
    elif is_flag_set("kubernetes-control-plane.secure-storage.created"):
        if not encryption_config_path().exists():
            hookenv.status_set(
                "blocked", "VaultLocker containing encryption config unavailable"
            )
            return

    vsphere_joined = is_state("endpoint.vsphere.joined")
    azure_joined = is_state("endpoint.azure.joined")
    cloud_blocked = is_state("kubernetes-control-plane.cloud.blocked")
    if vsphere_joined and cloud_blocked:
        hookenv.status_set(
            "blocked", "vSphere integration requires K8s 1.12 or greater"
        )
        return
    if azure_joined and cloud_blocked:
        hookenv.status_set("blocked", "Azure integration requires K8s 1.11 or greater")
        return
    if not is_flag_set("kubernetes.cni-plugins.installed"):
        hookenv.status_set("blocked", "Missing CNI resource")
        return
    if is_state("kubernetes-control-plane.cloud.pending"):
        hookenv.status_set("waiting", "Waiting for cloud integration")
        return

    if "kube-api-endpoint" in goal_state.get("relations", {}):
        if not is_state("kube-api-endpoint.available"):
            hookenv.status_set("waiting", "Waiting for kube-api-endpoint relation")
            return

    for lb_endpoint in ("loadbalancer-internal", "loadbalancer-external"):
        if lb_endpoint in goal_state.get("relations", {}):
            lb_provider = endpoint_from_name(lb_endpoint)
            if not lb_provider.has_response:
                hookenv.status_set("waiting", "Waiting for " + lb_endpoint)
                return

    ks = endpoint_from_flag("keystone-credentials.available")
    if ks and ks.api_version() == "2":
        msg = "Keystone auth v2 detected. v3 is required."
        hookenv.status_set("blocked", msg)
        return

    upgrade_needed = is_state("kubernetes-control-plane.upgrade-needed")
    upgrade_specified = is_state("kubernetes-control-plane.upgrade-specified")
    if upgrade_needed and not upgrade_specified:
        msg = "Needs manual upgrade, run the upgrade action"
        hookenv.status_set("blocked", msg)
        return

    try:
        get_dns_provider()
    except InvalidDnsProvider as e:
        if e.value == "core-dns":
            msg = "dns-provider=core-dns requires k8s 1.14+"
        else:
            msg = "dns-provider=%s is invalid" % e.value
        hookenv.status_set("blocked", msg)
        return

    if is_state("kubernetes-control-plane.vault-kv.pending"):
        hookenv.status_set(
            "waiting", "Waiting for encryption info from Vault to secure secrets"
        )
        return

    if is_state("kubernetes-control-plane.had-service-cidr-expanded"):
        hookenv.status_set(
            "waiting", "Waiting to retry updates for service-cidr expansion"
        )
        return

    if not is_state("etcd.available"):
        if "etcd" in goal_state.get("relations", {}):
            status = "waiting"
        else:
            status = "blocked"
        hookenv.status_set(status, "Waiting for etcd")
        return

    if not is_state("cni.available"):
        if "cni" in goal_state.get("relations", {}):
            hookenv.status_set("waiting", "Waiting for CNI plugins to become available")
            return
        elif not cni_config_exists() and (not hookenv.config("ignore-missing-cni")):
            hookenv.status_set("blocked", "Missing CNI relation or config")
            return

    if not is_state("tls_client.certs.saved"):
        hookenv.status_set("waiting", "Waiting for certificates")
        return

    if not is_flag_set("kubernetes-control-plane.auth-webhook-service.started"):
        hookenv.status_set("waiting", "Waiting for auth-webhook service to start")
        return

    if not is_flag_set("kubernetes-control-plane.apiserver.configured"):
        hookenv.status_set("waiting", "Waiting for API server to be configured")
        return

    if not is_flag_set("kubernetes-control-plane.apiserver.running"):
        hookenv.status_set("waiting", "Waiting for API server to start")
        return

    authentication_setup = is_state("authentication.setup")
    if not authentication_setup:
        hookenv.status_set("waiting", "Waiting for crypto keys.")
        return

    if not is_flag_set("kubernetes-control-plane.auth-webhook-tokens.setup"):
        hookenv.status_set("waiting", "Waiting for auth-webhook tokens")
        return

    if is_state("kubernetes-control-plane.components.started"):
        # All services should be up and running at this point. Double-check...
        failing_services = control_plane_services_down()
        if len(failing_services) != 0:
            msg = "Stopped services: {}".format(",".join(failing_services))
            hookenv.status_set("blocked", msg)
            if is_flag_set("ha.connected"):
                hookenv.log("Disabling node to pass resources to other nodes")
                cmd = "crm -w -F node standby"
                call(cmd.split())
            for service in failing_services:
                heal_handler = HEAL_HANDLER[service]
                for flag in heal_handler["clear_flags"]:
                    clear_flag(flag)
                heal_handler["run"]()
            set_flag("kubernetes-control-plane.components.failed")
            return
        else:
            if is_flag_set("kubernetes-control-plane.components.failed"):
                if is_flag_set("ha.connected"):
                    hookenv.log("Enabling node again to receive resources")
                    cmd = "crm -w -F node online"
                    call(cmd.split())
                clear_flag("kubernetes-control-plane.components.failed")

    else:
        # if we don't have components starting, we're waiting for that and
        # shouldn't fall through to Kubernetes control plane running.
        hookenv.status_set(
            "maintenance", "Waiting for control plane components to start"
        )
        return

    # Note that after this point, kubernetes-control-plane.components.started is
    # always True.

    is_leader = is_state("leadership.is_leader")
    addons_configured = is_state("cdk-addons.configured")
    if is_leader and not addons_configured:
        hookenv.status_set("waiting", "Waiting to retry addon deployment")
        return

    if is_leader and not is_state(
        "kubernetes-control-plane.system-monitoring-rbac-role.applied"
    ):
        msg = "Waiting to retry applying system:monitoring RBAC role"
        hookenv.status_set("waiting", msg)
        return

    try:
        unready = get_kube_system_pods_not_running()
    except FailedToGetPodStatus:
        hookenv.status_set("waiting", "Waiting for kube-system pods to start")
        return

    if unready:
        plural = "s" if len(unready) > 1 else ""
        msg = "Waiting for {} kube-system pod{} to start"
        msg = msg.format(len(unready), plural)
        hookenv.status_set("waiting", msg)
        return

    service_cidr = kubernetes_control_plane.service_cidr()
    if hookenv.config("service-cidr") != service_cidr:
        msg = "WARN: cannot change service-cidr, still using " + service_cidr
        hookenv.status_set("active", msg)
        return

    gpu_available = is_state("kube-control.gpu.available")
    gpu_enabled = is_state("kubernetes-control-plane.gpu.enabled")
    if gpu_available and not gpu_enabled:
        msg = 'GPUs available. Set allow-privileged="auto" to enable.'
        hookenv.status_set("active", msg)
        return

    if is_flag_set("ceph-storage.available"):
        hookenv.status_set(
            "blocked", "ceph-storage relation deprecated, use ceph-client instead"
        )
        return

    if is_flag_set("ceph-client.connected") and not is_flag_set(
        "ceph-client.available"
    ):
        hookenv.status_set("waiting", "Waiting for Ceph to provide a key.")
        return

    if (
        is_leader
        and ks
        and is_flag_set("kubernetes-control-plane.keystone-policy-error")
    ):
        hookenv.status_set("blocked", "Invalid keystone policy file.")
        return

    if (
        is_leader
        and ks
        and not is_flag_set("kubernetes-control-plane.keystone-policy-handled")
    ):
        hookenv.status_set("waiting", "Waiting to apply keystone policy file.")
        return

    if hookenv.config("enable-metrics") and not hookenv.config(
        "api-aggregation-extension"
    ):
        hookenv.status_set(
            "blocked",
            "metrics service will be unreachable without api-aggregation-extension.",
        )
        return

    hookenv.status_set("active", "Kubernetes control-plane running.")


def control_plane_services_down():
    """Ensure control plane services are up and running.

    Return: list of failing services"""
    return list(
        filterfalse(kubernetes_control_plane.check_service, control_plane_services)
    )


def add_systemd_file_limit():
    directory = "/etc/systemd/system/snap.kube-apiserver.daemon.service.d"
    if not os.path.isdir(directory):
        os.makedirs(directory)

    file_name = "file-limit.conf"
    path = os.path.join(directory, file_name)
    if not os.path.isfile(path):
        with open(path, "w") as f:
            f.write("[Service]\n")
            f.write("LimitNOFILE=65535")


def add_systemd_file_watcher():
    """Setup systemd file-watcher service.

    This service watches these files for changes:

    /root/cdk/known_tokens.csv
    /root/cdk/serviceaccount.key

    If a file is changed, the service uses juju-run to invoke a script in a
    hook context on this unit. If this unit is the leader, the script will
    call leader-set to distribute the contents of these files to the
    non-leaders so they can sync their local copies to match.

    """
    render(
        "cdk.master.leader.file-watcher.sh",
        "/usr/local/sbin/cdk.master.leader.file-watcher.sh",
        {},
        perms=0o755,
    )
    render(
        "cdk.master.leader.file-watcher.service",
        "/etc/systemd/system/cdk.master.leader.file-watcher.service",
        {"unit": hookenv.local_unit()},
        perms=0o644,
    )
    render(
        "cdk.master.leader.file-watcher.path",
        "/etc/systemd/system/cdk.master.leader.file-watcher.path",
        {},
        perms=0o644,
    )
    service_resume("cdk.master.leader.file-watcher.path")


@when("etcd.available", "tls_client.certs.saved")
@restart_on_change(
    {
        auth_webhook_conf: [auth_webhook_svc_name],
        auth_webhook_exe: [auth_webhook_svc_name],
        auth_webhook_svc: [auth_webhook_svc_name],
    }
)
def register_auth_webhook():
    """Render auth webhook templates and start the related service."""
    Path(auth_webhook_root).mkdir(exist_ok=True)

    # For 'api_ver', match the api version of the authentication.k8s.io TokenReview
    # that k8s-apiserver will be sending:
    #   https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18
    context = {
        "api_ver": "v1beta1",
        "charm_dir": hookenv.charm_dir(),
        "host": get_ingress_address(
            "kube-api-endpoint", ignore_addresses=[hookenv.config("ha-cluster-vip")]
        ),
        "pidfile": "{}.pid".format(auth_webhook_svc_name),
        "logfile": "{}.log".format(auth_webhook_svc_name),
        "port": 5000,
        "root_dir": auth_webhook_root,
    }

    context["aws_iam_endpoint"] = None
    if endpoint_from_flag("endpoint.aws-iam.ready"):
        aws_webhook = Path(aws_iam_webhook)
        if aws_webhook.exists():
            aws_yaml = yaml.safe_load(aws_webhook.read_text())
            try:
                context["aws_iam_endpoint"] = aws_yaml["clusters"][0]["cluster"][
                    "server"
                ]
            except (KeyError, TypeError):
                hookenv.log(
                    "Unable to find server in AWS IAM webhook: {}".format(aws_yaml)
                )
                pass

    context["keystone_endpoint"] = None
    if endpoint_from_flag("keystone-credentials.available"):
        ks_webhook = Path(keystone_root) / "webhook.yaml"
        if ks_webhook.exists():
            ks_yaml = yaml.safe_load(ks_webhook.read_text())
            try:
                context["keystone_endpoint"] = ks_yaml["clusters"][0]["cluster"][
                    "server"
                ]
            except (KeyError, TypeError):
                hookenv.log(
                    "Unable to find server in Keystone webhook: {}".format(ks_yaml)
                )
                pass

    context["custom_authn_endpoint"] = None
    custom_authn = hookenv.config("authn-webhook-endpoint")
    if custom_authn:
        context["custom_authn_endpoint"] = custom_authn

    k8s_log_path = Path(kubernetes_logs)
    k8s_log_path.mkdir(parents=True, exist_ok=True)  # ensure log path exists
    render("cdk.master.auth-webhook-conf.yaml", auth_webhook_conf, context)
    render("cdk.master.auth-webhook.py", auth_webhook_exe, context)
    render(
        "cdk.master.auth-webhook.logrotate", "/etc/logrotate.d/auth-webhook", context
    )

    # Move existing log files from ${auth_webhook_root} to /var/log/kubernetes/
    for log_file in Path(auth_webhook_root).glob("auth-webhook.log*"):
        # all historical log files (.log, .log.1 and .log.3.tgz)
        new_log_file = k8s_log_path / ("cdk.master." + log_file.name)
        if not new_log_file.exists():
            move(str(log_file), str(new_log_file))

    # Set the number of gunicorn workers based on our core count. (2*cores)+1 is
    # recommended: https://docs.gunicorn.org/en/stable/design.html#how-many-workers
    try:
        cores = int(check_output(["nproc"]).decode("utf-8").strip())
    except CalledProcessError:
        # Our default architecture is 2-cores for k8s-cp units
        cores = 2
    else:
        # Put an upper bound on cores; more than 12ish workers is overkill
        cores = 6 if cores > 6 else cores
    context["num_workers"] = cores * 2 + 1
    render("cdk.master.auth-webhook.service", auth_webhook_svc, context)
    if any_file_changed([auth_webhook_svc]):
        # if the service file has changed (or is new),
        # we have to inform systemd about it
        check_call(["systemctl", "daemon-reload"])
    if not is_flag_set("kubernetes-control-plane.auth-webhook-service.started"):
        if service_resume(auth_webhook_svc_name):
            set_flag("kubernetes-control-plane.auth-webhook-service.started")
            clear_flag("kubernetes-control-plane.apiserver.configured")
        else:
            hookenv.status_set(
                "maintenance", "Waiting for {} to start.".format(auth_webhook_svc_name)
            )
            hookenv.log("{} failed to start; will retry".format(auth_webhook_svc_name))


@when(
    "kubernetes-control-plane.apiserver.running",
    "kubernetes-control-plane.auth-webhook-service.started",
    "authentication.setup",
)
@when_not("kubernetes-control-plane.auth-webhook-tokens.setup")
def setup_auth_webhook_tokens():
    """Reconfigure authentication to setup auth-webhook tokens.

    If authentication has been setup with a non-auth-webhook configuration,
    convert it to use auth-webhook tokens instead. Alternatively, if the
    auth-webhook setup failed, this will also ensure that it is retried.
    """
    # Even if the apiserver is configured, it may not be fully started. Only
    # proceed if we can get secrets.
    if not kubectl_success("get", "secrets"):
        hookenv.log("Secrets are not yet available; will retry")
        return
    if create_tokens_and_sign_auth_requests():
        # Force setup_leader_authentication to be re-run.
        remove_state("authentication.setup")


@when(
    "etcd.available",
    "tls_client.certs.saved",
    "authentication.setup",
    "leadership.set.auto_storage_backend",
    "leadership.set.cluster_tag",
)
@when_not(
    "kubernetes-control-plane.components.started",
    "kubernetes-control-plane.cloud.pending",
    "kubernetes-control-plane.cloud.blocked",
    "kubernetes-control-plane.vault-kv.pending",
    "tls_client.certs.changed",
    "tls_client.ca.written",
    "upgrade.series.in-progress",
)
def start_control_plane():
    """Run the Kubernetes control-plane components."""
    hookenv.status_set(
        "maintenance", "Configuring the Kubernetes control plane services."
    )

    if not is_state("kubernetes-control-plane.vault-kv.pending") and not is_state(
        "kubernetes-control-plane.secure-storage.created"
    ):
        encryption_config_path().parent.mkdir(parents=True, exist_ok=True)
        host.write_file(
            path=str(encryption_config_path()),
            perms=0o600,
            content=yaml.safe_dump(
                {
                    "kind": "EncryptionConfig",
                    "apiVersion": "v1",
                    "resources": [
                        {"resources": ["secrets"], "providers": [{"identity": {}}]}
                    ],
                }
            ),
        )

    kubernetes_control_plane.freeze_service_cidr()

    etcd = endpoint_from_flag("etcd.available")
    if not etcd.get_connection_string():
        # etcd is not returning a connection string. This happens when
        # the control-plane unit disconnects from etcd and is ready to terminate.
        # No point in trying to start control-plane services and fail. Just return.
        return

    # TODO: Make sure below relation is handled on change
    # https://github.com/kubernetes/kubernetes/issues/43461
    handle_etcd_relation(etcd)

    # Set up additional systemd services
    add_systemd_restart_always(control_plane_services)
    add_systemd_file_limit()
    add_systemd_file_watcher()
    add_systemd_iptables_patch()
    check_call(["systemctl", "daemon-reload"])

    # Add CLI options to all components
    clear_flag("kubernetes-control-plane.apiserver.configured")
    configure_controller_manager()
    configure_scheduler()

    # kube-proxy
    cluster_cidr = kubernetes_common.cluster_cidr()
    if cluster_cidr and kubernetes_common.is_ipv6(cluster_cidr):
        kubernetes_common.enable_ipv6_forwarding()

    local_address = get_ingress_address("kube-api-endpoint")
    local_server = "https://{0}:{1}".format(local_address, 6443)

    configure_kube_proxy(configure_prefix, [local_server], cluster_cidr)
    service_restart("snap.kube-proxy.daemon")

    set_state("kubernetes-control-plane.components.started")
    hookenv.open_port(6443)


@when("config.changed.proxy-extra-args")
def proxy_args_changed():
    clear_flag("kubernetes-control-plane.components.started")
    clear_flag("config.changed.proxy-extra-args")


@when("tls_client.certs.changed")
def certs_changed():
    if service_running(auth_webhook_svc_name):
        service_restart(auth_webhook_svc_name)
    clear_flag("kubernetes-control-plane.components.started")
    clear_flag("tls_client.certs.changed")


@when("tls_client.ca.written")
def ca_written():
    clear_flag("kubernetes-control-plane.components.started")
    if is_state("leadership.is_leader"):
        if leader_get("kubernetes-master-addons-ca-in-use"):
            leader_set({"kubernetes-master-addons-restart-for-ca": True})
    clear_flag("tls_client.ca.written")
    clear_flag("kubernetes-control-plane.kubelet.configured")


@when("etcd.available")
def etcd_data_change(etcd):
    """Etcd scale events block control-plane reconfiguration due to the
    kubernetes-control-plane.components.started state. We need a way to
    handle these events consistently only when the number of etcd
    units has actually changed"""

    # key off of the connection string
    connection_string = etcd.get_connection_string()

    # If the connection string changes, remove the started state to trigger
    # handling of the control-plane components
    if data_changed("etcd-connect", connection_string):
        remove_state("kubernetes-control-plane.components.started")

    # If the cert info changes, remove the started state to trigger
    # handling of the control-plane components
    if data_changed("etcd-certs", etcd.get_client_credentials()):
        clear_flag("kubernetes-control-plane.components.started")

    # We are the leader and the auto_storage_backend is not set meaning
    # this is the first time we connect to etcd.
    auto_storage_backend = leader_get("auto_storage_backend")
    is_leader = is_state("leadership.is_leader")
    if is_leader and not auto_storage_backend:
        if etcd.get_version().startswith("3."):
            leader_set(auto_storage_backend="etcd3")
        else:
            leader_set(auto_storage_backend="etcd2")


def get_dns_info():
    dns_provider = endpoint_from_flag("dns-provider.available")
    try:
        goal_state_rels = hookenv.goal_state().get("relations", {})
    except NotImplementedError:
        goal_state_rels = {}
    dns_provider_missing = not dns_provider and "dns-provider" not in goal_state_rels
    dns_provider_pending = not dns_provider and "dns-provider" in goal_state_rels
    try:
        dns_disabled_cfg = get_dns_provider() == "none"
    except InvalidDnsProvider:
        dns_disabled_cfg = False
    if dns_provider_missing and dns_disabled_cfg:
        return True, None, None, None
    elif dns_provider_pending:
        return False, None, None, None
    elif dns_provider:
        details = dns_provider.details()
        return True, details["sdn-ip"], details["port"], details["domain"]
    else:
        try:
            dns_provider = get_dns_provider()
        except InvalidDnsProvider:
            hookenv.log(traceback.format_exc())
            return False, None, None, None
        dns_domain = hookenv.config("dns_domain")
        dns_ip = None
        try:
            dns_ip = kubernetes_control_plane.get_dns_ip()
        except CalledProcessError:
            hookenv.log("DNS addon service not ready yet")
            return False, None, None, None
        return True, dns_ip, 53, dns_domain


@when("kube-control.connected")
@when("cdk-addons.configured")
def send_cluster_dns_detail(kube_control):
    """Send cluster DNS info"""
    dns_ready, dns_ip, dns_port, dns_domain = get_dns_info()
    if dns_ready:
        kube_control.set_dns(dns_port, dns_domain, dns_ip, dns_ip is not None)


def create_tokens_and_sign_auth_requests():
    """Create tokens for CK users and services."""
    clear_flag("kubernetes-control-plane.auth-webhook-tokens.setup")
    # NB: This may be called before kube-apiserver is up when bootstrapping new
    # clusters with auth-webhook. In this case, setup_tokens will be a no-op.
    # We will re-enter this function once control plane services are available to
    # create proper secrets.
    controller_manager_token = get_token("system:kube-controller-manager")
    if not controller_manager_token:
        setup_tokens(None, "system:kube-controller-manager", "kube-controller-manager")

    proxy_token = get_token("system:kube-proxy")
    if not proxy_token:
        setup_tokens(None, "system:kube-proxy", "kube-proxy")
        proxy_token = get_token("system:kube-proxy")

    scheduler_token = get_token("system:kube-scheduler")
    if not scheduler_token:
        setup_tokens(None, "system:kube-scheduler", "system:kube-scheduler")

    client_token = get_token("admin")
    if not client_token:
        setup_tokens(None, "admin", "admin", "system:masters")
        client_token = get_token("admin")

    monitoring_token = get_token("system:monitoring")
    if not monitoring_token:
        setup_tokens(None, "system:monitoring", "system:monitoring")

    if not (proxy_token and client_token):
        # When bootstrapping a new cluster, we may not have all our secrets yet.
        # Do not let the kubelets start without all the needed tokens.
        hookenv.log(
            "Missing required tokens for kubelet startup; will retry", hookenv.WARNING
        )
        return False

    kube_control = endpoint_from_flag("kube-control.connected")
    requests = kube_control.auth_user() if kube_control else []
    any_failed = False
    for request in requests:
        username = request[1]["user"]
        group = request[1]["group"]
        if not username or not group:
            continue
        kubelet_token = get_token(username)
        if not kubelet_token:
            # Username will be in the form of system:node:<nodeName>.
            # User ID will be a worker <unitName>, and while not used today, we store
            # this in case it becomes useful to map a secret to a unit in the future.
            userid = request[0]
            setup_tokens(None, username, userid, group)
            kubelet_token = get_token(username)
        if not kubelet_token:
            hookenv.log(
                "Failed to create token for {}; will retry".format(username),
                hookenv.WARNING,
            )
            any_failed = True
            continue
        kube_control.sign_auth_request(
            request[0], username, kubelet_token, proxy_token, client_token
        )
    if not any_failed:
        set_flag("kubernetes-control-plane.auth-webhook-tokens.setup")
        return True
    else:
        return False


@when("kube-api-endpoint.available")
def push_service_data():
    """Send configuration to the load balancer, and close access to the
    public interface.
    """
    kube_api = endpoint_from_flag("kube-api-endpoint.available")

    endpoints = kubernetes_control_plane.get_endpoints_from_config()
    if endpoints:
        addresses = [e[0] for e in endpoints]
        kube_api.configure(
            kubernetes_control_plane.STANDARD_API_PORT, addresses, addresses
        )
    else:
        # no manually configured LBs, so rely on the interface layer
        # to use the ingress address for each relation
        kube_api.configure(kubernetes_control_plane.STANDARD_API_PORT)


@when("leadership.is_leader")
@when_any(
    "endpoint.loadbalancer-internal.available",
    "endpoint.loadbalancer-external.available",
)
def request_load_balancers():
    """Request LBs from the related provider(s)."""
    for lb_type in ("internal", "external"):
        lb_provider = endpoint_from_name("loadbalancer-" + lb_type)
        if not lb_provider.is_available:
            continue
        req = lb_provider.get_request("api-server-" + lb_type)
        req.protocol = req.protocols.tcp
        ext_api_port = kubernetes_control_plane.EXTERNAL_API_PORT
        int_api_port = kubernetes_control_plane.STANDARD_API_PORT
        api_port = ext_api_port if lb_type == "external" else int_api_port
        req.port_mapping = {api_port: int_api_port}
        req.public = lb_type == "external"
        if not req.health_checks:
            req.add_health_check(
                protocol=req.protocols.http,
                port=int_api_port,
                path="/livez",
            )
        lb_provider.send_request(req)


@when("kube-control.connected")
def send_api_urls():
    kube_control = endpoint_from_name("kube-control")
    if not hasattr(kube_control, "set_api_endpoints"):
        # built with an old version of the kube-control interface
        # the old kube-api-endpoint relation must be used instead
        return
    endpoints = kubernetes_control_plane.get_internal_api_endpoints()
    if not endpoints:
        return
    kube_control.set_api_endpoints(kubernetes_control_plane.get_api_urls(endpoints))


def has_external_cloud_provider() -> bool:
    has_xcp = bool(hookenv.relations().get("external-cloud-provider"))
    if data_changed("has-xcp", has_xcp):
        set_flag("external-cloud-provider.changed")
    return has_xcp


@when("kube-control.connected")
def send_xcp_flag():
    has_xcp = has_external_cloud_provider()
    kube_control = endpoint_from_name("kube-control")
    kube_control.set_has_xcp(has_xcp)


@when("certificates.available")
def send_data():
    """Send the data that is required to create a server certificate for
    this server."""
    # Use the public ip of this unit as the Common Name for the certificate.
    common_name = hookenv.unit_public_ip()

    # Get the SDN gateways based on the service CIDRs.
    k8s_service_ips = kubernetes_control_plane.get_kubernetes_service_ips()

    bind_ips = kubernetes_common.get_bind_addrs()

    # Get ingress address (this is probably already covered by bind_ips,
    # but list it explicitly as well just in case it's not).
    old_ingress_ip = get_ingress_address("kube-api-endpoint")
    new_ingress_ip = get_ingress_address("kube-control")

    local_endpoint = kubernetes_control_plane.get_local_api_endpoint()[0][0]

    domain = hookenv.config("dns_domain")
    # Create SANs that the tls layer will add to the server cert.
    sans = (
        [
            # The CN field is checked as a hostname, so if it's an IP, it
            # won't match unless also included in the SANs as an IP field.
            common_name,
            local_endpoint,
            old_ingress_ip,
            new_ingress_ip,
            socket.gethostname(),
            socket.getfqdn(),
            "kubernetes",
            "kubernetes.{0}".format(domain),
            "kubernetes.default",
            "kubernetes.default.svc",
            "kubernetes.default.svc.{0}".format(domain),
        ]
        + k8s_service_ips
        + bind_ips
    )

    sans.extend(e[0] for e in kubernetes_control_plane.get_internal_api_endpoints())
    sans.extend(e[0] for e in kubernetes_control_plane.get_external_api_endpoints())

    # maybe they have extra names they want as SANs
    extra_sans = hookenv.config("extra_sans")
    if extra_sans and not extra_sans == "":
        sans.extend(extra_sans.split())

    # Request a server cert with this information.
    tls_client.request_server_cert(
        common_name,
        sorted(set(sans)),
        crt_path=server_crt_path,
        key_path=server_key_path,
    )

    # Request a client cert for kubelet.
    tls_client.request_client_cert(
        "system:kube-apiserver", crt_path=client_crt_path, key_path=client_key_path
    )


@when(
    "config.changed.extra_sans", "certificates.available", "kube-api-endpoint.available"
)
def update_certificates():
    # NOTE: This handler may be called by another function. Two relationships
    # are required, otherwise the send_data function fails.
    # (until the relations are available)
    missing_relations = get_unset_flags(
        "certificates.available", "kube-api-endpoint.available"
    )
    if missing_relations:
        hookenv.log(
            "Missing relations: '{}'".format(", ".join(missing_relations)),
            hookenv.ERROR,
        )
        return

    # Using the config.changed.extra_sans flag to catch changes.
    # IP changes will take ~5 minutes or so to propagate, but
    # it will update.
    send_data()
    clear_flag("config.changed.extra_sans")


@when(
    "kubernetes-control-plane.components.started",
    "leadership.is_leader",
    "cdk-addons.reconfigure",
)
def reconfigure_cdk_addons():
    configure_cdk_addons()


def apply_default_storage(storage_class, def_storage_class):
    name = storage_class["metadata"]["name"]
    is_default = name == def_storage_class
    cur_annotations = storage_class["metadata"].get("annotations") or {}
    new_annotations = cur_annotations.copy()
    storage_class_annotation = "storageclass.kubernetes.io/is-default-class"
    if is_default:
        new_annotations.update(**{storage_class_annotation: "true"})
    elif not is_default and storage_class_annotation in new_annotations:
        new_annotations.pop(storage_class_annotation)

    if new_annotations != cur_annotations:
        hookenv.log(
            f"{'S' if is_default else 'Uns'}etting default storage-class {name}.",
            hookenv.INFO,
        )
        patch_set = json.dumps(dict(metadata=new_annotations))
        kubectl("patch", "storageclass", name, "-p", patch_set)


def storage_classes():
    try:
        storage_classes = json.loads(kubectl("get", "storageclass", "-o=json").decode())
    except (CalledProcessError, FileNotFoundError):
        hookenv.log("Failed to get the current storage classes.", hookenv.WARNING)
        hookenv.log(traceback.format_exc())
        storage_classes = dict(items=[])
    for storage_class in storage_classes["items"]:
        yield storage_class


@when("config.changed.default-storage")
def configure_default_storage_class():
    def_storage_class = hookenv.config("default-storage")
    if def_storage_class == "auto":
        def_storage_class = "ceph-xfs"
    for storage_class in storage_classes():
        apply_default_storage(storage_class, def_storage_class)
    return def_storage_class


@when(
    "kubernetes-control-plane.components.started",
    "leadership.is_leader",
    "leadership.set.cluster_tag",
)
@when_not("upgrade.series.in-progress")
def configure_cdk_addons():
    """Configure CDK addons"""
    remove_state("cdk-addons.reconfigure")
    remove_state("cdk-addons.configured")
    remove_state("kubernetes-control-plane.aws.changed")
    remove_state("kubernetes-control-plane.azure.changed")
    remove_state("kubernetes-control-plane.gcp.changed")
    remove_state("kubernetes-control-plane.openstack.changed")
    load_gpu_plugin = hookenv.config("enable-nvidia-plugin").lower()
    kube_version = get_version("kube-apiserver")
    gpuEnable = (
        kube_version >= (1, 9)
        and load_gpu_plugin == "auto"
        and is_state("kubernetes-control-plane.gpu.enabled")
    )
    registry = hookenv.config("image-registry")
    dbEnabled = str(hookenv.config("enable-dashboard-addons")).lower()
    try:
        dnsProvider = get_dns_provider()
    except InvalidDnsProvider:
        hookenv.log(traceback.format_exc())
        return
    metricsEnabled = str(hookenv.config("enable-metrics")).lower()
    default_storage = configure_default_storage_class()
    ceph = {}
    ceph_ep = endpoint_from_flag("ceph-client.available")
    cephfs_mounter = hookenv.config("cephfs-mounter")
    cephEnabled = "false"
    cephFsEnabled = "false"
    if ceph_ep and ceph_ep.key and ceph_ep.mon_hosts():
        kubernetes_control_plane.install_ceph_common()
        ceph_fsid = kubernetes_control_plane.get_ceph_fsid()
        if ceph_fsid:
            cephEnabled = "true"
            b64_ceph_key = base64.b64encode(ceph_ep.key.encode("utf-8"))
            ceph["admin_key"] = b64_ceph_key.decode("ascii")
            ceph["fsid"] = ceph_fsid
            ceph["kubernetes_key"] = b64_ceph_key.decode("ascii")
            ceph["mon_hosts"] = " ".join(ceph_ep.mon_hosts())

            if kubernetes_control_plane.query_cephfs_enabled():
                cephFsEnabled = "true"
                ceph["fsname"] = kubernetes_control_plane.get_cephfs_fsname() or ""

    keystone = {}
    ks = endpoint_from_flag("keystone-credentials.available")
    if ks:
        keystoneEnabled = "true"
        keystone["cert"] = "/root/cdk/server.crt"
        keystone["key"] = "/root/cdk/server.key"
        keystone["url"] = "{}://{}:{}/v{}".format(
            ks.credentials_protocol(),
            ks.credentials_host(),
            ks.credentials_port(),
            ks.api_version(),
        )
        keystone["keystone-ca"] = hookenv.config("keystone-ssl-ca")
    else:
        keystoneEnabled = "false"

    # cdk-addons storage classes
    if kube_version < (1, 25, 0):
        enable_aws = str(is_flag_set("endpoint.aws.ready")).lower()
        enable_azure = str(is_flag_set("endpoint.azure.ready")).lower()
        enable_gcp = str(is_flag_set("endpoint.gcp.ready")).lower()
    else:
        enable_aws = enable_azure = enable_gcp = "false"
    enable_openstack = str(is_flag_set("endpoint.openstack.ready")).lower()
    openstack = endpoint_from_flag("endpoint.openstack.ready")

    if is_state("kubernetes-control-plane.cdk-addons.unique-cluster-tag"):
        cluster_tag = leader_get("cluster_tag")
    else:
        # allow for older upgraded charms to control when they start sending
        # the unique cluster tag to cdk-addons
        cluster_tag = "kubernetes"

    args = [
        "kubeconfig=" + cdk_addons_kubectl_config_path,
        "arch=" + arch(),
        "dns-domain=" + hookenv.config("dns_domain"),
        "registry=" + registry,
        "enable-dashboard=" + dbEnabled,
        "enable-metrics=" + metricsEnabled,
        "enable-gpu=" + str(gpuEnable).lower(),
        "enable-ceph=" + cephEnabled,
        "enable-cephfs=" + cephFsEnabled,
        "cephfs-mounter=" + cephfs_mounter,
        "ceph-admin-key=" + (ceph.get("admin_key", "")),
        "ceph-fsid=" + (ceph.get("fsid", "")),
        "ceph-fsname=" + (ceph.get("fsname", "")),
        "ceph-kubernetes-key=" + (ceph.get("admin_key", "")),
        'ceph-mon-hosts="' + (ceph.get("mon_hosts", "")) + '"',
        "ceph-user=" + hookenv.application_name(),
        "cinder-availability-zone=" + hookenv.config("cinder-availability-zone"),
        "default-storage=" + default_storage,
        "enable-keystone=" + keystoneEnabled,
        "keystone-cert-file=" + keystone.get("cert", ""),
        "keystone-key-file=" + keystone.get("key", ""),
        "keystone-server-url=" + keystone.get("url", ""),
        "keystone-server-ca=" + keystone.get("keystone-ca", ""),
        "dashboard-auth=token",
        "enable-aws=" + enable_aws,
        "enable-azure=" + enable_azure,
        "enable-gcp=" + enable_gcp,
        "enable-openstack=" + enable_openstack,
        "cluster-tag=" + cluster_tag,
    ]
    if openstack:
        args.extend(
            [
                "openstack-cloud-conf="
                + base64.b64encode(
                    generate_openstack_cloud_config().encode("utf-8")
                ).decode("utf-8"),
                "openstack-endpoint-ca=" + (openstack.endpoint_tls_ca or ""),
            ]
        )
    args.append("dns-provider=" + dnsProvider)
    check_call(["snap", "set", "cdk-addons"] + args)
    if not addons_ready():
        remove_state("cdk-addons.configured")
        return

    set_state("cdk-addons.configured")
    leader_set({"kubernetes-master-addons-ca-in-use": True})
    if ks:
        leader_set({"keystone-cdk-addons-configured": True})
    else:
        leader_set({"keystone-cdk-addons-configured": None})


@retry(times=3, delay_secs=20)
def addons_ready():
    """
    Test if the add ons got installed

    Returns: True is the addons got applied

    """
    try:
        check_call(["cdk-addons.apply"])
        return True
    except CalledProcessError:
        hookenv.log("Addons are not ready yet.")
        return False


@when("ceph-client.connected")
@when_not("kubernetes-control-plane.ceph.pools.created")
def ceph_storage_pool():
    """Once Ceph relation is ready,
    we need to add storage pools.

    :return: None
    """
    hookenv.log("Creating Ceph pools.")
    ceph_client = endpoint_from_flag("ceph-client.connected")

    pools = ["xfs-pool", "ext4-pool"]

    for pool in pools:
        hookenv.status_set("maintenance", "Creating {} pool.".format(pool))
        try:
            ceph_client.create_pool(name=pool, replicas=3)
        except Exception as e:
            hookenv.status_set("blocked", "Error creating {} pool: {}.".format(pool, e))

    set_state("kubernetes-control-plane.ceph.pools.created")


@when("nrpe-external-master.available")
@when_not("nrpe-external-master.initial-config")
def initial_nrpe_config():
    set_state("nrpe-external-master.initial-config")
    update_nrpe_config()


@when("config.changed.authorization-mode")
def switch_auth_mode(forced=False):
    config = hookenv.config()
    mode = config.get("authorization-mode")

    if data_changed("auth-mode", mode) or forced:
        # manage flags to handle rbac related resources
        if mode and "rbac" in mode.lower():
            remove_state("kubernetes-control-plane.remove.rbac")
            set_state("kubernetes-control-plane.create.rbac")
        else:
            remove_state("kubernetes-control-plane.create.rbac")
            set_state("kubernetes-control-plane.remove.rbac")

        # set ourselves up to restart since auth mode has changed
        remove_state("kubernetes-control-plane.components.started")


@when("leadership.is_leader", "kubernetes-control-plane.components.started")
@when_not("kubernetes-control-plane.pod-security-policy.applied")
def create_pod_security_policy_resources():
    if get_version("kube-apiserver")[:2] < (1, 25):
        pod_security_policy_path = "/root/cdk/pod-security-policy.yaml"
        pod_security_policy = hookenv.config("pod-security-policy")
        if pod_security_policy:
            hookenv.log("Using configuration defined on pod-security-policy option")
            write_file_with_autogenerated_header(
                pod_security_policy_path, pod_security_policy
            )
        else:
            hookenv.log("Using the default rbac-pod-security-policy template")
            render("rbac-pod-security-policy.yaml", pod_security_policy_path, {})

        hookenv.log("Creating pod security policy resources.")
        if kubectl_manifest("apply", pod_security_policy_path):
            set_state("kubernetes-control-plane.pod-security-policy.applied")
        else:
            msg = "Failed to apply {}, will retry.".format(pod_security_policy_path)
            hookenv.log(msg)
    else:
        pod_security_policy = hookenv.config("pod-security-policy")
        if pod_security_policy:
            hookenv.status_set(
                "blocked",
                "PodSecurityPolicy not available in 1.25+,"
                " please remove pod-security-policy config",
            )
        else:
            set_state("kubernetes-control-plane.pod-security-policy.applied")


@when(
    "leadership.is_leader",
    "kubernetes-control-plane.components.started",
    "kubernetes-control-plane.create.rbac",
)
def create_rbac_resources():
    rbac_proxy_path = "/root/cdk/rbac-proxy.yaml"

    # NB: when metrics and logs are retrieved by proxy, the 'user' is the
    # common name of the cert used to authenticate the proxied request.
    # The CN for /root/cdk/client.crt is 'system:kube-apiserver'
    # (see the send_data handler, above).
    proxy_users = ["client", "system:kube-apiserver"]

    context = {"juju_application": hookenv.service_name(), "proxy_users": proxy_users}
    render("rbac-proxy.yaml", rbac_proxy_path, context)

    hookenv.log("Creating proxy-related RBAC resources.")
    if kubectl_manifest("apply", rbac_proxy_path):
        remove_state("kubernetes-control-plane.create.rbac")
    else:
        msg = "Failed to apply {}, will retry.".format(rbac_proxy_path)
        hookenv.log(msg)


@when("leadership.is_leader", "kubernetes-control-plane.components.started")
@when_not("kubernetes-control-plane.system-monitoring-rbac-role.applied")
def apply_system_monitoring_rbac_role():
    try:
        hookenv.status_set("maintenance", "Applying system:monitoring RBAC role")
        path = "/root/cdk/system-monitoring-rbac-role.yaml"
        render("system-monitoring-rbac-role.yaml", path, {})
        kubectl("apply", "-f", path)
        set_state("kubernetes-control-plane.system-monitoring-rbac-role.applied")
    except Exception:
        hookenv.log(traceback.format_exc())
        hookenv.log("Waiting to retry applying system:monitoring RBAC role")
        return


@when(
    "leadership.is_leader",
    "kubernetes-control-plane.components.started",
    "kubernetes-control-plane.remove.rbac",
)
def remove_rbac_resources():
    rbac_proxy_path = "/root/cdk/rbac-proxy.yaml"
    if os.path.isfile(rbac_proxy_path):
        hookenv.log("Removing proxy-related RBAC resources.")
        if kubectl_manifest("delete", rbac_proxy_path):
            os.remove(rbac_proxy_path)
            remove_state("kubernetes-control-plane.remove.rbac")
        else:
            msg = "Failed to delete {}, will retry.".format(rbac_proxy_path)
            hookenv.log(msg)
    else:
        # if we dont have the yaml, there's nothing for us to do
        remove_state("kubernetes-control-plane.remove.rbac")


@when("kubernetes-control-plane.components.started")
@when("nrpe-external-master.available")
@when_any("config.changed.nagios_context", "config.changed.nagios_servicegroups")
def update_nrpe_config():
    services = ["snap.{}.daemon".format(s) for s in control_plane_services]
    services += [auth_webhook_svc_name]

    plugin = install_nagios_plugin_from_file(
        "templates/nagios_plugin.py", "check_k8s_master.py"
    )
    hostname = nrpe.get_nagios_hostname()
    current_unit = nrpe.get_nagios_unit_name()
    nrpe_setup = nrpe.NRPE(hostname=hostname)
    nrpe.add_init_service_checks(nrpe_setup, services, current_unit)
    nrpe_setup.add_check(
        "k8s-api-server",
        "Verify that the Kubernetes API server is accessible",
        str(plugin),
    )
    nrpe_setup.write()


@when_not("nrpe-external-master.available")
@when("nrpe-external-master.initial-config")
def remove_nrpe_config():
    # List of systemd services for which the checks will be removed
    services = ["snap.{}.daemon".format(s) for s in control_plane_services]

    remove_nagios_plugin("check_k8s_master.py")

    # The current nrpe-external interface doesn't handle a lot of logic,
    # use the charm-helpers code for now.
    hostname = nrpe.get_nagios_hostname()
    nrpe_setup = nrpe.NRPE(hostname=hostname)

    for service in services:
        nrpe_setup.remove_check(shortname=service)
    nrpe_setup.remove_check(shortname="k8s-api-server")
    remove_state("nrpe-external-master.initial-config")


def is_privileged():
    """Return boolean indicating whether or not to set allow-privileged=true."""
    privileged = hookenv.config("allow-privileged").lower()
    if privileged == "auto":
        return (
            is_state("kubernetes-control-plane.gpu.enabled")
            or is_state("ceph-client.available")
            or is_state("endpoint.openstack.joined")
        )
    else:
        return privileged == "true"


@when("config.changed.allow-privileged")
@when("kubernetes-control-plane.components.started")
def on_config_allow_privileged_change():
    """React to changed 'allow-privileged' config value."""
    remove_state("kubernetes-control-plane.components.started")
    remove_state("config.changed.allow-privileged")


@when_any(
    "config.changed.api-extra-args",
    "config.changed.audit-policy",
    "config.changed.audit-webhook-config",
    "config.changed.enable-keystone-authorization",
    "config.changed.service-cidr",
)
@when("kubernetes-control-plane.components.started")
@when("leadership.set.auto_storage_backend")
@when("etcd.available")
def reconfigure_apiserver():
    clear_flag("kubernetes-control-plane.apiserver.configured")


@when("config.changed.controller-manager-extra-args")
@when("kubernetes-control-plane.components.started")
def on_config_controller_manager_extra_args_change():
    configure_controller_manager()


@when("config.changed.scheduler-extra-args")
@when("kubernetes-control-plane.components.started")
def on_config_scheduler_extra_args_change():
    configure_scheduler()


@when("kube-control.gpu.available")
@when("kubernetes-control-plane.components.started")
@when_not("kubernetes-control-plane.gpu.enabled")
def on_gpu_available(kube_control):
    """The remote side (kubernetes-worker) is gpu-enabled.

    We need to run in privileged mode.

    """
    kube_version = get_version("kube-apiserver")
    config = hookenv.config()
    if config["allow-privileged"].lower() == "false" and kube_version < (1, 9):
        return

    remove_state("kubernetes-control-plane.components.started")
    set_state("kubernetes-control-plane.gpu.enabled")


@when("kubernetes-control-plane.gpu.enabled")
@when("kubernetes-control-plane.components.started")
@when_not("kubernetes-control-plane.privileged")
def gpu_with_no_privileged():
    """We were in gpu mode, but the operator has set allow-privileged="false",
    so we can't run in gpu mode anymore.

    """
    if get_version("kube-apiserver") < (1, 9):
        remove_state("kubernetes-control-plane.gpu.enabled")


@when("kube-control.connected")
@when_not("kube-control.gpu.available")
@when("kubernetes-control-plane.gpu.enabled")
@when("kubernetes-control-plane.components.started")
def gpu_departed(kube_control):
    """We were in gpu mode, but the workers informed us there is
    no gpu support anymore.

    """
    remove_state("kubernetes-control-plane.gpu.enabled")


@hook("stop")
def shutdown():
    """Stop the kubernetes control-plane services"""
    for service in control_plane_services:
        service_stop("snap.%s.daemon" % service)


@when(
    "certificates.ca.available",
    "certificates.client.cert.available",
    "authentication.setup",
)
def build_kubeconfig():
    """Gather the relevant data for Kubernetes configuration objects and create
    a config object with that information."""
    local_endpoint = kubernetes_control_plane.get_local_api_endpoint()
    internal_endpoints = kubernetes_control_plane.get_internal_api_endpoints()
    external_endpoints = kubernetes_control_plane.get_external_api_endpoints()

    # Do we have everything we need?
    if ca_crt_path.exists() and internal_endpoints and external_endpoints:
        local_url = kubernetes_control_plane.get_api_url(local_endpoint)
        internal_url = kubernetes_control_plane.get_api_url(internal_endpoints)
        external_url = kubernetes_control_plane.get_api_url(external_endpoints)
        client_pass = get_token("admin")
        if not client_pass:
            # If we made it this far without a password, we're bootstrapping a new
            # cluster. Create a new token so we can build an admin kubeconfig. The
            # auth-webhook service will ack this value from the kubeconfig file,
            # allowing us to continue until the control-plane is started and a proper
            # secret can be created.
            client_pass = (
                hookenv.config("client_password")
                or kubernetes_control_plane.token_generator()
            )
            client_pass = "admin::{}".format(client_pass)

        # drop keystone helper script?
        ks = endpoint_from_flag("keystone-credentials.available")
        if ks:
            script_filename = "kube-keystone.sh"
            keystone_path = os.path.join(os.sep, "home", "ubuntu", script_filename)
            context = {
                "protocol": ks.credentials_protocol(),
                "address": ks.credentials_host(),
                "port": ks.credentials_port(),
                "version": ks.api_version(),
            }
            render(script_filename, keystone_path, context)
        elif is_state("leadership.set.keystone-cdk-addons-configured"):
            # if addons are configured, we're going to do keystone
            # just not yet because we don't have creds
            hookenv.log("Keystone endpoint not found, will retry.")

        cluster_id = None
        aws_iam = endpoint_from_flag("endpoint.aws-iam.available")
        if aws_iam:
            cluster_id = aws_iam.get_cluster_id()

        # Create an absolute path for the kubeconfig file.
        kubeconfig_path = os.path.join(os.sep, "home", "ubuntu", "config")

        # Create the kubeconfig on this system so users can access the cluster.
        hookenv.log("Writing kubeconfig file.")

        if ks:
            create_kubeconfig(
                kubeconfig_path,
                external_url,
                ca_crt_path,
                user="admin",
                token=client_pass,
                keystone=True,
                aws_iam_cluster_id=cluster_id,
            )
        else:
            create_kubeconfig(
                kubeconfig_path,
                external_url,
                ca_crt_path,
                user="admin",
                token=client_pass,
                aws_iam_cluster_id=cluster_id,
            )

        # Make the config file readable by the ubuntu users so juju scp works.
        cmd = ["chown", "ubuntu:ubuntu", kubeconfig_path]
        check_call(cmd)

        # make a kubeconfig for root / the charm
        create_kubeconfig(
            kubeclientconfig_path,
            local_url,
            ca_crt_path,
            user="admin",
            token=client_pass,
        )

        # Create kubernetes configuration in the default location for ubuntu.
        create_kubeconfig(
            "/home/ubuntu/.kube/config",
            internal_url,
            ca_crt_path,
            user="admin",
            token=client_pass,
        )
        # Make the config dir readable by the ubuntu user
        check_call(["chown", "-R", "ubuntu:ubuntu", "/home/ubuntu/.kube"])

        # make a kubeconfig for cdk-addons
        create_kubeconfig(
            cdk_addons_kubectl_config_path,
            local_url,
            ca_crt_path,
            user="admin",
            token=client_pass,
        )

        # make a kubeconfig for our services
        proxy_token = get_token("system:kube-proxy")
        if proxy_token:
            create_kubeconfig(
                kubeproxyconfig_path,
                local_url,
                ca_crt_path,
                token=proxy_token,
                user="kube-proxy",
            )
        controller_manager_token = get_token("system:kube-controller-manager")
        if controller_manager_token:
            create_kubeconfig(
                kubecontrollermanagerconfig_path,
                local_url,
                ca_crt_path,
                token=controller_manager_token,
                user="kube-controller-manager",
            )
        scheduler_token = get_token("system:kube-scheduler")
        if scheduler_token:
            create_kubeconfig(
                kubeschedulerconfig_path,
                local_url,
                ca_crt_path,
                token=scheduler_token,
                user="kube-scheduler",
            )

        cni = endpoint_from_name("cni")
        if cni:
            cni.notify_kubeconfig_changed()


def handle_etcd_relation(reldata):
    """Save the client credentials and set appropriate daemon flags when
    etcd declares itself as available"""
    # Define where the etcd tls files will be kept.
    etcd_dir = "/root/cdk/etcd"

    # Create paths to the etcd client ca, key, and cert file locations.
    ca = os.path.join(etcd_dir, "client-ca.pem")
    key = os.path.join(etcd_dir, "client-key.pem")
    cert = os.path.join(etcd_dir, "client-cert.pem")

    # Save the client credentials (in relation data) to the paths provided.
    reldata.save_client_credentials(key, cert, ca)


def remove_if_exists(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def write_file_with_autogenerated_header(path, contents):
    with open(path, "w") as f:
        header = "# Autogenerated by kubernetes-control-plane charm"
        f.write(header + "\n" + contents)


@when(
    "etcd.available",
    "kubernetes-control-plane.auth-webhook-service.started",
)
@when_not("kubernetes-control-plane.apiserver.configured")
def configure_apiserver():
    etcd_connection_string = endpoint_from_flag(
        "etcd.available"
    ).get_connection_string()
    if not etcd_connection_string:
        # etcd is not returning a connection string. This happens when
        # the control-plane unit disconnects from etcd and is ready to terminate.
        # No point in trying to start control-plane services and fail. Just return.
        return

    # Update unit db service-cidr
    was_service_cidr_expanded = kubernetes_control_plane.is_service_cidr_expansion()
    kubernetes_control_plane.freeze_service_cidr()

    cluster_cidr = kubernetes_common.cluster_cidr()
    service_cidr = kubernetes_control_plane.service_cidr()

    # Share service_cidr with cni requirers
    cni = endpoint_from_flag("cni.available")
    if cni:
        cni.set_service_cidr(service_cidr)

    api_opts = {}
    kube_version = get_version("kube-apiserver")

    if is_privileged():
        api_opts["allow-privileged"] = "true"
        set_state("kubernetes-control-plane.privileged")
    else:
        api_opts["allow-privileged"] = "false"
        remove_state("kubernetes-control-plane.privileged")

    # Handle static options for now
    api_opts["service-cluster-ip-range"] = service_cidr
    feature_gates = []
    api_opts["min-request-timeout"] = "300"
    api_opts["v"] = "4"
    api_opts["tls-cert-file"] = str(server_crt_path)
    api_opts["tls-private-key-file"] = str(server_key_path)
    api_opts["tls-cipher-suites"] = ",".join(tls_ciphers_intermediate)
    api_opts["kubelet-certificate-authority"] = str(ca_crt_path)
    api_opts["kubelet-client-certificate"] = str(client_crt_path)
    api_opts["kubelet-client-key"] = str(client_key_path)
    if kube_version < (1, 26, 0):
        api_opts["logtostderr"] = "true"
    api_opts["storage-backend"] = getStorageBackend()
    api_opts["profiling"] = "false"

    api_opts["anonymous-auth"] = "false"
    api_opts["authentication-token-webhook-cache-ttl"] = "1m0s"
    api_opts["authentication-token-webhook-config-file"] = auth_webhook_conf
    api_opts["service-account-issuer"] = "https://kubernetes.default.svc"
    api_opts["service-account-signing-key-file"] = "/root/cdk/serviceaccount.key"
    api_opts["service-account-key-file"] = "/root/cdk/serviceaccount.key"
    api_opts[
        "kubelet-preferred-address-types"
    ] = "InternalIP,Hostname,InternalDNS,ExternalDNS,ExternalIP"
    api_opts["encryption-provider-config"] = str(encryption_config_path())
    if cluster_cidr and kubernetes_common.is_ipv6_preferred(cluster_cidr):
        api_opts["advertise-address"] = get_ingress_address6("kube-control")
    else:
        api_opts["advertise-address"] = get_ingress_address("kube-control")

    etcd_dir = "/root/cdk/etcd"
    etcd_ca = os.path.join(etcd_dir, "client-ca.pem")
    etcd_key = os.path.join(etcd_dir, "client-key.pem")
    etcd_cert = os.path.join(etcd_dir, "client-cert.pem")

    api_opts["etcd-cafile"] = etcd_ca
    api_opts["etcd-keyfile"] = etcd_key
    api_opts["etcd-certfile"] = etcd_cert
    api_opts["etcd-servers"] = etcd_connection_string

    # In Kubernetes 1.10 and later, some admission plugins are enabled by
    # default. The current list of default plugins can be found at
    # https://bit.ly/2meP9XT, listed under the '--enable-admission-plugins'
    # option.
    #
    # The list below need only include the plugins we want to enable
    # in addition to the defaults.

    # PodSecurityPolicy was removed in 1.25
    if kube_version >= (1, 25):
        admission_plugins = [
            "PersistentVolumeLabel",
            "NodeRestriction",
        ]
    else:
        admission_plugins = [
            "PersistentVolumeLabel",
            "PodSecurityPolicy",
            "NodeRestriction",
        ]

    auth_mode = hookenv.config("authorization-mode")

    ks = endpoint_from_flag("keystone-credentials.available")
    if ks:
        ks_ip = get_service_ip("k8s-keystone-auth-service", errors_fatal=False)
        if ks_ip:
            os.makedirs(keystone_root, exist_ok=True)

            keystone_webhook = keystone_root + "/webhook.yaml"
            context = {}
            context["keystone_service_cluster_ip"] = ks_ip
            render("keystone-api-server-webhook.yaml", keystone_webhook, context)

            if hookenv.config("enable-keystone-authorization"):
                # if user wants authorization, enable it
                if "Webhook" not in auth_mode:
                    auth_mode += ",Webhook"
                api_opts["authorization-webhook-config-file"] = keystone_webhook  # noqa
            set_state("keystone.apiserver.configured")
        else:
            hookenv.log("Unable to find k8s-keystone-auth-service. Will retry")
            # Note that we can get into a nasty state here
            # if the user has specified webhook and they're relying on
            # keystone auth to handle that, the api server will fail to
            # start because we push it Webhook and no webhook config.
            # We can't generate the config because we can't talk to the
            # apiserver to get the ip of the service to put into the
            # webhook template. A chicken and egg problem. To fix this,
            # remove Webhook if keystone is related and trying to come
            # up until we can find the service IP.
            if "Webhook" in auth_mode:
                auth_mode = ",".join(
                    [i for i in auth_mode.split(",") if i != "Webhook"]
                )
            remove_state("keystone.apiserver.configured")
    elif is_state("leadership.set.keystone-cdk-addons-configured"):
        hookenv.log("Keystone endpoint not found, will retry.")

    api_opts["authorization-mode"] = auth_mode
    api_opts["enable-admission-plugins"] = ",".join(admission_plugins)

    if kube_version > (1, 6) and hookenv.config("api-aggregation-extension"):
        api_opts["requestheader-client-ca-file"] = str(ca_crt_path)
        api_opts["requestheader-allowed-names"] = "system:kube-apiserver,client"
        api_opts["requestheader-extra-headers-prefix"] = "X-Remote-Extra-"
        api_opts["requestheader-group-headers"] = "X-Remote-Group"
        api_opts["requestheader-username-headers"] = "X-Remote-User"
        api_opts["proxy-client-cert-file"] = str(client_crt_path)
        api_opts["proxy-client-key-file"] = str(client_key_path)
        api_opts["enable-aggregator-routing"] = "true"
        api_opts["client-ca-file"] = str(ca_crt_path)

    api_cloud_config_path = cloud_config_path("kube-apiserver")
    if has_external_cloud_provider():
        api_opts["cloud-provider"] = "external"
    elif is_state("endpoint.aws.ready"):
        if kube_version < (1, 27, 0):
            api_opts["cloud-provider"] = "aws"
        else:
            hookenv.log(
                "AWS cloud-provider is no longer available in-tree. "
                "the out-of-tree provider is necessary",
                level="WARNING",
            )
        if kube_version < (1, 25, 0):
            feature_gates.append("CSIMigrationAWS=false")
    elif is_state("endpoint.gcp.ready"):
        api_opts["cloud-provider"] = "gce"
        api_opts["cloud-config"] = str(api_cloud_config_path)
        if kube_version < (1, 25, 0):
            feature_gates.append("CSIMigrationGCE=false")
    elif is_state("endpoint.vsphere.ready"):
        if (1, 12) <= kube_version:
            api_opts["cloud-provider"] = "vsphere"
            api_opts["cloud-config"] = str(api_cloud_config_path)
        if kube_version < (1, 26, 0):
            feature_gates.append("CSIMigrationvSphere=false")
    elif is_state("endpoint.azure.ready"):
        api_opts["cloud-provider"] = "azure"
        api_opts["cloud-config"] = str(api_cloud_config_path)
        if kube_version < (1, 25, 0):
            feature_gates.append("CSIMigrationAzureDisk=false")

    api_opts["feature-gates"] = ",".join(feature_gates)

    audit_root = "/root/cdk/audit"
    os.makedirs(audit_root, exist_ok=True)

    audit_log_path = audit_root + "/audit.log"
    api_opts["audit-log-path"] = audit_log_path
    api_opts["audit-log-maxage"] = "30"
    api_opts["audit-log-maxsize"] = "100"
    api_opts["audit-log-maxbackup"] = "10"

    audit_policy_path = audit_root + "/audit-policy.yaml"
    audit_policy = hookenv.config("audit-policy")
    if audit_policy:
        write_file_with_autogenerated_header(audit_policy_path, audit_policy)
        api_opts["audit-policy-file"] = audit_policy_path
    else:
        remove_if_exists(audit_policy_path)

    audit_webhook_config_path = audit_root + "/audit-webhook-config.yaml"
    audit_webhook_config = hookenv.config("audit-webhook-config")
    if audit_webhook_config:
        write_file_with_autogenerated_header(
            audit_webhook_config_path, audit_webhook_config
        )
        api_opts["audit-webhook-config-file"] = audit_webhook_config_path
    else:
        remove_if_exists(audit_webhook_config_path)

    configure_kubernetes_service(
        configure_prefix, "kube-apiserver", api_opts, "api-extra-args"
    )
    service_restart("snap.kube-apiserver.daemon")

    if was_service_cidr_expanded and is_state("leadership.is_leader"):
        set_flag("kubernetes-control-plane.had-service-cidr-expanded")

    set_flag("kubernetes-control-plane.apiserver.configured")
    if kubernetes_control_plane.check_service("kube-apiserver"):
        set_flag("kubernetes-control-plane.apiserver.running")


@when("kubernetes-control-plane.apiserver.configured")
@when_not("kubernetes-control-plane.apiserver.running")
def check_apiserver():
    if kubernetes_control_plane.check_service("kube-apiserver"):
        set_flag("kubernetes-control-plane.apiserver.running")


@when(
    "kubernetes-control-plane.had-service-cidr-expanded",
    "kubernetes-control-plane.apiserver.configured",
    "leadership.is_leader",
)
def update_for_service_cidr_expansion():
    # We just restarted the API server, so there's a decent chance it's
    # not up yet. Keep trying to get the svcs list until we can; get_svcs
    # has a built-in retry and delay, so this should try for around 30s.
    def _wait_for_svc_ip():
        for attempt in range(10):
            svcs = get_svcs()
            if svcs:
                svc_ip = {
                    svc["metadata"]["name"]: svc["spec"]["clusterIP"]
                    for svc in svcs["items"]
                }.get("kubernetes")
                if svc_ip:
                    return svc_ip
        else:
            return None

    hookenv.log("service-cidr expansion: Waiting for API service")
    # First network is the default, which is used for the API service's address.
    # This logic will likely need to change once dual-stack services are
    # supported: https://bit.ly/2YlbxOx
    expected_service_ip = kubernetes_control_plane.get_kubernetes_service_ips()[0]
    actual_service_ip = _wait_for_svc_ip()
    if not actual_service_ip:
        hookenv.log("service-cidr expansion: Timed out waiting for API service")
        return
    try:
        if actual_service_ip != expected_service_ip:
            hookenv.log("service-cidr expansion: Deleting service kubernetes")
            kubectl("delete", "service", "kubernetes")
            actual_service_ip = _wait_for_svc_ip()
            if not actual_service_ip:
                # we might need another restart to get the service recreated
                hookenv.log(
                    "service-cidr expansion: Timed out waiting for "
                    "the service to return; restarting API server"
                )
                clear_flag("kubernetes-control-plane.apiserver.configured")
                return
            if actual_service_ip != expected_service_ip:
                raise ValueError(
                    "Unexpected service IP: {} != {}".format(
                        actual_service_ip, expected_service_ip
                    )
                )

        # Restart the cdk-addons
        # Get deployments/daemonsets/statefulsets
        hookenv.log("service-cidr expansion: Restart the cdk-addons")
        output = kubectl(
            "get",
            "daemonset,deployment,statefulset",
            "-o",
            "json",
            "--all-namespaces",
            "-l",
            "cdk-restart-on-ca-change=true",
        ).decode("UTF-8")
        deployments = json.loads(output)["items"]

        # Now restart the addons
        for deployment in deployments:
            kind = deployment["kind"]
            namespace = deployment["metadata"]["namespace"]
            name = deployment["metadata"]["name"]
            hookenv.log("Restarting addon: {0} {1} {2}".format(kind, namespace, name))
            kubectl("rollout", "restart", kind + "/" + name, "-n", namespace)
    except CalledProcessError:
        # the kubectl calls already log the command and don't capture stderr,
        # so logging the exception is a bit superfluous
        hookenv.log("service-cidr expansion: failed to restart components")
    else:
        clear_flag("kubernetes-control-plane.had-service-cidr-expanded")


def configure_controller_manager():
    controller_opts = {}
    cluster_cidr = kubernetes_common.cluster_cidr()
    service_cidr = kubernetes_control_plane.service_cidr()
    kube_version = get_version("kube-controller-manager")

    # Default to 3 minute resync. TODO: Make this configurable?
    controller_opts["min-resync-period"] = "3m"
    controller_opts["v"] = "2"
    controller_opts["root-ca-file"] = str(ca_crt_path)
    if kube_version < (1, 26, 0):
        controller_opts["logtostderr"] = "true"
    controller_opts["kubeconfig"] = kubecontrollermanagerconfig_path
    controller_opts["authorization-kubeconfig"] = kubecontrollermanagerconfig_path
    controller_opts["authentication-kubeconfig"] = kubecontrollermanagerconfig_path
    controller_opts["use-service-account-credentials"] = "true"
    controller_opts["service-account-private-key-file"] = "/root/cdk/serviceaccount.key"
    controller_opts["tls-cert-file"] = str(server_crt_path)
    controller_opts["tls-private-key-file"] = str(server_key_path)
    controller_opts["cluster-name"] = leader_get("cluster_tag")
    controller_opts["terminated-pod-gc-threshold"] = "12500"
    controller_opts["profiling"] = "false"
    controller_opts["service-cluster-ip-range"] = service_cidr
    if cluster_cidr:
        controller_opts["cluster-cidr"] = cluster_cidr
    feature_gates = ["RotateKubeletServerCertificate=true"]

    cm_cloud_config_path = cloud_config_path("kube-controller-manager")
    if has_external_cloud_provider():
        controller_opts["cloud-provider"] = "external"
    elif is_state("endpoint.aws.ready"):
        if kube_version < (1, 27, 0):
            controller_opts["cloud-provider"] = "aws"
        else:
            hookenv.log(
                "AWS cloud-provider is no longer available in-tree. "
                "the out-of-tree provider is necessary",
                level="WARNING",
            )
        if kube_version < (1, 25, 0):
            feature_gates.append("CSIMigrationAWS=false")
    elif is_state("endpoint.gcp.ready"):
        controller_opts["cloud-provider"] = "gce"
        controller_opts["cloud-config"] = str(cm_cloud_config_path)
        if kube_version < (1, 25, 0):
            feature_gates.append("CSIMigrationGCE=false")
    elif is_state("endpoint.vsphere.ready"):
        if (1, 12) <= kube_version:
            controller_opts["cloud-provider"] = "vsphere"
            controller_opts["cloud-config"] = str(cm_cloud_config_path)
        if kube_version < (1, 26, 0):
            feature_gates.append("CSIMigrationvSphere=false")
    elif is_state("endpoint.azure.ready"):
        controller_opts["cloud-provider"] = "azure"
        controller_opts["cloud-config"] = str(cm_cloud_config_path)
        if kube_version < (1, 25, 0):
            feature_gates.append("CSIMigrationAzureDisk=false")

    controller_opts["feature-gates"] = ",".join(feature_gates)

    configure_kubernetes_service(
        configure_prefix,
        "kube-controller-manager",
        controller_opts,
        "controller-manager-extra-args",
    )
    service_restart("snap.kube-controller-manager.daemon")


def configure_scheduler():
    kube_scheduler_config_path = "/root/cdk/kube-scheduler-config.yaml"
    kube_version = get_version("kube-scheduler")
    scheduler_opts = {}

    scheduler_opts["v"] = "2"
    if kube_version < (1, 26, 0):
        scheduler_opts["logtostderr"] = "true"
    scheduler_opts["config"] = kube_scheduler_config_path

    feature_gates = []

    if is_state("endpoint.aws.ready"):
        if kube_version < (1, 25, 0):
            feature_gates.append("CSIMigrationAWS=false")
    elif is_state("endpoint.gcp.ready"):
        if kube_version < (1, 25, 0):
            feature_gates.append("CSIMigrationGCE=false")
    elif is_state("endpoint.azure.ready"):
        if kube_version < (1, 25, 0):
            feature_gates.append("CSIMigrationAzureDisk=false")
    elif is_state("endpoint.vsphere.ready"):
        if (1, 12) <= kube_version < (1, 26, 0):
            feature_gates.append("CSIMigrationvSphere=false")

    scheduler_opts["feature-gates"] = ",".join(feature_gates)
    scheduler_config = {
        "kind": "KubeSchedulerConfiguration",
        "clientConnection": {"kubeconfig": kubeschedulerconfig_path},
    }

    if kube_version >= (1, 25):
        scheduler_config["apiVersion"] = "kubescheduler.config.k8s.io/v1"
        scheduler_config.update(
            enableContentionProfiling=False,
            enableProfiling=False,
        )
    elif kube_version >= (1, 23):
        scheduler_config["apiVersion"] = "kubescheduler.config.k8s.io/v1beta2"
        scheduler_config.update(
            enableContentionProfiling=False,
            enableProfiling=False,
        )
    elif kube_version >= (1, 19):
        scheduler_config["apiVersion"] = "kubescheduler.config.k8s.io/v1beta1"
        scheduler_opts["profiling"] = "false"
    elif kube_version >= (1, 18):
        scheduler_config["apiVersion"] = "kubescheduler.config.k8s.io/v1alpha2"
        scheduler_opts["profiling"] = "false"
    else:
        scheduler_config["apiVersion"] = "kubescheduler.config.k8s.io/v1alpha1"
        scheduler_opts["profiling"] = "false"

    host.write_file(
        path=kube_scheduler_config_path,
        perms=0o600,
        content=(
            "# Generated by kubernetes_control_plane charm, do not edit\n"
            + yaml.safe_dump(scheduler_config)
        ),
    )

    configure_kubernetes_service(
        configure_prefix, "kube-scheduler", scheduler_opts, "scheduler-extra-args"
    )

    service_restart("snap.kube-scheduler.daemon")


def setup_tokens(token, username, user, groups=None):
    """Create a token for kubernetes authentication.

    Create a new secret if known_tokens have been migrated. Otherwise,
    add an entry to the 'known_tokens.csv' file.
    """
    if not token:
        token = kubernetes_control_plane.token_generator()
    if is_flag_set("kubernetes-control-plane.token-auth.migrated"):
        # We need the apiserver before we can create secrets.
        if is_flag_set("kubernetes-control-plane.apiserver.configured"):
            kubernetes_control_plane.create_secret(token, username, user, groups)
        else:
            hookenv.log("Delaying secret creation until the apiserver is configured.")
    else:
        kubernetes_control_plane.create_known_token(token, username, user, groups)


def get_token(username):
    """Fetch a token for the given username.

    Grab a token from the given user's secret if known_tokens have been
    migrated. Otherwise, fetch it from the 'known_tokens.csv' file.
    """
    if is_flag_set("kubernetes-control-plane.token-auth.migrated"):
        return kubernetes_common.get_secret_password(username)
    else:
        return kubernetes_control_plane.get_csv_password("known_tokens.csv", username)


def set_token(password, save_salt):
    """Store a token so it can be recalled later by token_generator.

    param: password - the password to be stored
    param: save_salt - the key to store the value of the token."""
    db.set(save_salt, password)
    return db.get(save_salt)


@retry(times=3, delay_secs=1)
def get_pods(namespace="default"):
    try:
        output = kubectl(
            "get", "po", "-n", namespace, "-o", "json", "--request-timeout", "10s"
        ).decode("UTF-8")
        result = json.loads(output)
    except CalledProcessError:
        hookenv.log("failed to get {} pod status".format(namespace))
        return None
    return result


@retry(times=3, delay_secs=1)
def get_svcs(namespace="default"):
    try:
        output = kubectl(
            "get", "svc", "-n", namespace, "-o", "json", "--request-timeout", "10s"
        ).decode("UTF-8")
        result = json.loads(output)
    except CalledProcessError:
        hookenv.log("failed to get {} service status".format(namespace))
        return None
    return result


class FailedToGetPodStatus(Exception):
    pass


def get_kube_system_pods_not_running():
    """Check pod status in the kube-system namespace. Throws
    FailedToGetPodStatus if unable to determine pod status. This can
    occur when the api server is not currently running. On success,
    returns a list of pods that are not currently running
    or an empty list if all are running, ignoring pods whose names
    start with those provided in the ignore-kube-system-pods config option."""

    result = get_pods("kube-system")
    if result is None:
        raise FailedToGetPodStatus

    # Remove pods whose names start with ones provided in the ignore list
    pod_names_space_separated = hookenv.config("ignore-kube-system-pods")
    ignore_list = pod_names_space_separated.strip().split()
    result["items"] = [
        pod
        for pod in result["items"]
        if not any(pod["metadata"]["name"].startswith(name) for name in ignore_list)
    ]

    hookenv.log(
        "Checking system pods status: {}".format(
            ", ".join(
                "=".join([pod["metadata"]["name"], pod["status"]["phase"]])
                for pod in result["items"]
            )
        )
    )

    # Pods in phases such as ['Running', 'Succeeded', 'Failed']
    # should not be considered as pending Pods.
    valid_phases = ["Running", "Succeeded", "Failed"]

    # Pods that are Running or Evicted (which should re-spawn) are
    # considered running
    not_running = [
        pod
        for pod in result["items"]
        if pod["status"]["phase"] not in valid_phases
        and pod["status"].get("reason", "") != "Evicted"
    ]

    pending = [pod for pod in result["items"] if pod["status"]["phase"] == "Pending"]
    any_pending = len(pending) > 0
    if is_state("endpoint.gcp.ready") and any_pending:
        poke_network_unavailable()
        return not_running

    return not_running


def poke_network_unavailable():
    """
    Work around https://github.com/kubernetes/kubernetes/issues/44254 by
    manually poking the status into the API server to tell the nodes they have
    a network route.

    This is needed because kubelet sets the NetworkUnavailable flag and expects
    the network plugin to clear it, which only kubenet does. There is some
    discussion about refactoring the affected code but nothing has happened
    in a while.
    """
    internal_endpoints = kubernetes_control_plane.get_internal_api_endpoints()
    internal_url = kubernetes_control_plane.get_api_url(internal_endpoints)

    client_token = get_token("admin")
    http_header = ("Authorization", "Bearer {}".format(client_token))

    try:
        output = kubectl("get", "nodes", "-o", "json").decode("utf-8")
        nodes = json.loads(output)["items"]
    except CalledProcessError:
        hookenv.log("failed to get kube-system nodes")
        return
    except (KeyError, json.JSONDecodeError) as e:
        hookenv.log(
            "failed to parse kube-system node status " "({}): {}".format(e, output),
            hookenv.ERROR,
        )
        return

    for node in nodes:
        node_name = node["metadata"]["name"]
        url = "{}/api/v1/nodes/{}/status".format(internal_url, node_name)
        req = Request(url)
        req.add_header(*http_header)
        with urlopen(req) as response:
            code = response.getcode()
            body = response.read().decode("utf8")
        if code != 200:
            hookenv.log(
                "failed to get node status from {} [{}]: {}".format(url, code, body),
                hookenv.ERROR,
            )
            return
        try:
            node_info = json.loads(body)
            conditions = node_info["status"]["conditions"]
            network_unavail_idx = [
                idx
                for idx, c in enumerate(conditions)
                if c["type"] == "NetworkUnavailable" and c["status"] == "True"
            ]
            if network_unavail_idx:
                hookenv.log("Clearing NetworkUnavailable from {}".format(node_name))
                i, *_ = network_unavail_idx
                conditions[i] = {
                    "type": "NetworkUnavailable",
                    "status": "False",
                    "reason": "RouteCreated",
                    "message": "Manually set through k8s api",
                }
                req = Request(
                    url,
                    method="PUT",
                    data=json.dumps(node_info).encode("utf8"),
                    headers={"Content-Type": "application/json"},
                )
                req.add_header(*http_header)
                with urlopen(req) as response:
                    code = response.getcode()
                    body = response.read().decode("utf8")
                if code not in (200, 201, 202):
                    hookenv.log(
                        "failed to update node status [{}]: {}".format(code, body),
                        hookenv.ERROR,
                    )
                    return
        except (json.JSONDecodeError, KeyError):
            hookenv.log("failed to parse node status: {}".format(body), hookenv.ERROR)
            return


def apiserverVersion():
    cmd = "kube-apiserver --version".split()
    version_string = check_output(cmd).decode("utf-8")
    return tuple(int(q) for q in re.findall("[0-9]+", version_string)[:3])


def touch(fname):
    try:
        os.utime(fname, None)
    except OSError:
        open(fname, "a").close()


def getStorageBackend():
    storage_backend = hookenv.config("storage-backend")
    if storage_backend == "auto":
        storage_backend = leader_get("auto_storage_backend")
    return storage_backend


@when("leadership.is_leader")
@when_not("leadership.set.cluster_tag")
def create_cluster_tag():
    cluster_tag = "kubernetes-{}".format(
        kubernetes_control_plane.token_generator().lower()
    )
    leader_set(cluster_tag=cluster_tag)


@when("leadership.set.cluster_tag", "kube-control.connected")
def send_cluster_tag():
    cluster_tag = leader_get("cluster_tag")
    kube_control = endpoint_from_flag("kube-control.connected")
    kube_control.set_cluster_tag(cluster_tag)


@when_not("kube-control.connected")
def clear_cluster_tag_sent():
    remove_state("kubernetes-control-plane.cluster-tag-sent")


@when_any(
    "endpoint.aws.joined",
    "endpoint.gcp.joined",
    "endpoint.openstack.joined",
    "endpoint.vsphere.joined",
    "endpoint.azure.joined",
)
@when_not("kubernetes-control-plane.cloud.ready")
def set_cloud_pending():
    k8s_version = get_version("kube-apiserver")
    k8s_1_11 = k8s_version >= (1, 11)
    k8s_1_12 = k8s_version >= (1, 12)
    vsphere_joined = is_state("endpoint.vsphere.joined")
    azure_joined = is_state("endpoint.azure.joined")
    if (vsphere_joined and not k8s_1_12) or (azure_joined and not k8s_1_11):
        set_state("kubernetes-control-plane.cloud.blocked")
    else:
        remove_state("kubernetes-control-plane.cloud.blocked")
    set_state("kubernetes-control-plane.cloud.pending")


@when_any("endpoint.aws.joined", "endpoint.gcp.joined", "endpoint.azure.joined")
@when("leadership.set.cluster_tag")
@when_not("kubernetes-control-plane.cloud.request-sent")
def request_integration():
    hookenv.status_set("maintenance", "requesting cloud integration")
    cluster_tag = leader_get("cluster_tag")
    if is_state("endpoint.aws.joined"):
        cloud = endpoint_from_flag("endpoint.aws.joined")
        cloud.tag_instance(
            {
                "kubernetes.io/cluster/{}".format(cluster_tag): "owned",
                "k8s.io/role/master": "true",  # wokeignore:rule=master
            }
        )
        cloud.tag_instance_security_group(
            {
                "kubernetes.io/cluster/{}".format(cluster_tag): "owned",
            }
        )
        cloud.tag_instance_subnet(
            {
                "kubernetes.io/cluster/{}".format(cluster_tag): "owned",
            }
        )
        cloud.enable_object_storage_management(["kubernetes-*"])
        cloud.enable_load_balancer_management()

        # Necessary for cloud-provider-aws
        cloud.enable_autoscaling_readonly()
        cloud.enable_instance_modification()
        cloud.enable_region_readonly()
    elif is_state("endpoint.gcp.joined"):
        cloud = endpoint_from_flag("endpoint.gcp.joined")
        cloud.label_instance(
            {
                "k8s-io-cluster-name": cluster_tag,
                "k8s-io-role-master": "master",  # wokeignore:rule=master
            }
        )
        cloud.enable_object_storage_management()
        cloud.enable_security_management()
    elif is_state("endpoint.azure.joined"):
        cloud = endpoint_from_flag("endpoint.azure.joined")
        cloud.tag_instance(
            {
                "k8s-io-cluster-name": cluster_tag,
                "k8s-io-role-master": "master",  # wokeignore:rule=master
            }
        )
        cloud.enable_object_storage_management()
        cloud.enable_security_management()
        cloud.enable_loadbalancer_management()
    cloud.enable_instance_inspection()
    cloud.enable_network_management()
    cloud.enable_dns_management()
    cloud.enable_block_storage_management()
    set_state("kubernetes-control-plane.cloud.request-sent")


@when_none(
    "endpoint.aws.joined",
    "endpoint.gcp.joined",
    "endpoint.openstack.joined",
    "endpoint.vsphere.joined",
    "endpoint.azure.joined",
)
@when_any(
    "kubernetes-control-plane.cloud.pending",
    "kubernetes-control-plane.cloud.request-sent",
    "kubernetes-control-plane.cloud.blocked",
    "kubernetes-control-plane.cloud.ready",
)
def clear_cloud_flags():
    remove_state("kubernetes-control-plane.cloud.pending")
    remove_state("kubernetes-control-plane.cloud.request-sent")
    remove_state("kubernetes-control-plane.cloud.blocked")
    remove_state("kubernetes-control-plane.cloud.ready")
    clear_flag("kubernetes-control-plane.apiserver.configured")
    clear_flag("kubernetes-control-plane.kubelet.configured")
    _kick_controller_manager()


@when_any(
    "endpoint.aws.ready",
    "endpoint.gcp.ready",
    "endpoint.openstack.ready",
    "endpoint.vsphere.ready",
    "endpoint.azure.ready",
)
@when_not(
    "kubernetes-control-plane.cloud.blocked", "kubernetes-control-plane.cloud.ready"
)
def cloud_ready():
    if is_state("endpoint.gcp.ready"):
        write_gcp_snap_config("kube-apiserver")
        write_gcp_snap_config("kube-controller-manager")
        write_gcp_snap_config("kubelet")
    elif is_state("endpoint.vsphere.ready"):
        _write_vsphere_snap_config("kube-apiserver")
        _write_vsphere_snap_config("kube-controller-manager")
    elif is_state("endpoint.azure.ready"):
        write_azure_snap_config("kube-apiserver")
        write_azure_snap_config("kube-controller-manager")
        write_azure_snap_config("kubelet")
    remove_state("kubernetes-control-plane.cloud.pending")
    set_state("kubernetes-control-plane.cloud.ready")
    remove_state("kubernetes-control-plane.components.started")  # force restart


@when("kubernetes-control-plane.cloud.ready")
@when_any(
    "endpoint.openstack.ready.changed",
    "endpoint.vsphere.ready.changed",
    "endpoint.azure.ready.changed",
)
def update_cloud_config():
    """Signal that cloud config has changed.

    Some clouds (openstack, vsphere) support runtime config that needs to be
    reflected in the k8s cloud config files when changed. Manage flags to
    ensure this happens.
    """
    if is_state("endpoint.openstack.ready.changed"):
        remove_state("endpoint.openstack.ready.changed")
        set_state("kubernetes-control-plane.openstack.changed")
    if is_state("endpoint.vsphere.ready.changed"):
        remove_state("kubernetes-control-plane.cloud.ready")
        remove_state("endpoint.vsphere.ready.changed")
    if is_state("endpoint.azure.ready.changed"):
        remove_state("kubernetes-control-plane.cloud.ready")
        remove_state("endpoint.azure.ready.changed")


def _cdk_addons_template_path():
    return Path("/snap/cdk-addons/current/templates")


def _write_vsphere_snap_config(component):
    # vsphere requires additional cloud config
    vsphere = endpoint_from_flag("endpoint.vsphere.ready")

    # NB: vsphere provider will ask kube-apiserver and -controller-manager to
    # find a uuid from sysfs unless a global config value is set. Our strict
    # snaps cannot read sysfs, so let's do it in the charm. An invalid uuid is
    # not fatal for storage, but it will muddy the logs; try to get it right.
    uuid = _get_vmware_uuid()

    comp_cloud_config_path = cloud_config_path(component)
    comp_cloud_config_path.write_text(
        "\n".join(
            [
                "[Global]",
                "insecure-flag = true",
                'datacenters = "{}"'.format(vsphere.datacenter),
                'vm-uuid = "VMware-{}"'.format(uuid),
                '[VirtualCenter "{}"]'.format(vsphere.vsphere_ip),
                'user = "{}"'.format(vsphere.user),
                'password = "{}"'.format(vsphere.password),
                "[Workspace]",
                'server = "{}"'.format(vsphere.vsphere_ip),
                'datacenter = "{}"'.format(vsphere.datacenter),
                'default-datastore = "{}"'.format(vsphere.datastore),
                'folder = "{}"'.format(vsphere.folder),
                'resourcepool-path = "{}"'.format(vsphere.respool_path),
                "[Disk]",
                'scsicontrollertype = "pvscsi"',
            ]
        )
    )


@when("config.changed.keystone-policy")
@when("kubernetes-control-plane.keystone-policy-handled")
def regen_keystone_policy():
    clear_flag("kubernetes-control-plane.keystone-policy-handled")


@when(
    "keystone-credentials.available",
    "leadership.is_leader",
    "kubernetes-control-plane.apiserver.configured",
)
@when_not("kubernetes-control-plane.keystone-policy-handled")
def generate_keystone_configmap():
    keystone_policy = hookenv.config("keystone-policy")
    if keystone_policy:
        os.makedirs(keystone_root, exist_ok=True)
        write_file_with_autogenerated_header(keystone_policy_path, keystone_policy)
        if kubectl_manifest("apply", keystone_policy_path):
            set_flag("kubernetes-control-plane.keystone-policy-handled")
            clear_flag("kubernetes-control-plane.keystone-policy-error")
        else:
            set_flag("kubernetes-control-plane.keystone-policy-error")
    else:
        # a missing policy configmap will crashloop the pods, but...
        # what do we do in this situation. We could just do nothing,
        # but that isn't cool for the user so we surface an error
        # and wait for them to fix it.
        set_flag("kubernetes-control-plane.keystone-policy-error")

    # note that information is surfaced to the user in the code above where we
    # write status. It will notify the user we are waiting on the policy file
    # to apply if the keystone-credentials.available flag is set, but
    # kubernetes-control-plane.keystone-policy-handled is not set.


@when("leadership.is_leader", "kubernetes-control-plane.keystone-policy-handled")
@when_not("keystone-credentials.available")
def remove_keystone():
    clear_flag("kubernetes-control-plane.apiserver.configured")
    if not os.path.exists(keystone_policy_path):
        clear_flag("kubernetes-control-plane.keystone-policy-handled")
    elif kubectl_manifest("delete", keystone_policy_path):
        os.remove(keystone_policy_path)
        clear_flag("kubernetes-control-plane.keystone-policy-handled")


@when("keystone-credentials.connected")
def setup_keystone_user():
    # This seems silly, but until we request a user from keystone
    # we don't get information about the keystone server...
    ks = endpoint_from_flag("keystone-credentials.connected")
    ks.request_credentials("k8s")


def _kick_controller_manager():
    if is_flag_set("kubernetes-control-plane.components.started"):
        configure_controller_manager()


@when(
    "keystone.credentials.configured", "leadership.set.keystone-cdk-addons-configured"
)
@when_not("keystone.apiserver.configured")
def keystone_kick_apiserver():
    clear_flag("kubernetes-control-plane.apiserver.configured")


@when(
    "keystone-credentials.available",
    "certificates.ca.available",
    "certificates.client.cert.available",
    "authentication.setup",
    "etcd.available",
    "leadership.set.keystone-cdk-addons-configured",
)
def keystone_config():
    # first, we have to have the service set up before we can render this stuff
    ks = endpoint_from_flag("keystone-credentials.available")
    data = {
        "host": ks.credentials_host(),
        "proto": ks.credentials_protocol(),
        "port": ks.credentials_port(),
        "version": ks.api_version(),
    }
    if data_changed("keystone", data):
        remove_state("keystone.credentials.configured")
        clear_flag("kubernetes-control-plane.apiserver.configured")
        build_kubeconfig()
        generate_keystone_configmap()
        set_state("keystone.credentials.configured")


def maybe_heal_vault_kv():
    if not is_state("kubernetes-control-plane.secure-storage.created"):
        return

    migrate = False
    vault = endpoint_from_flag("vault-kv.connected")
    secret_backend = vault_kv._get_secret_backend()
    for relation in vault.relations:
        if relation.to_publish["secret_backend"] != secret_backend:
            # trigger a new vault_access request in layer-vault-kv
            # the secrets backend has changed and we need to ensure the
            # current encryption_secret isn't lost
            hookenv.log("Need to migrate to new secrets backend")
            clear_flag("layer.vault-kv.requested")
            migrate = True

    if not is_state("leadership.is_leader"):
        hookenv.log("Vault healing complete for non-leader")
        return

    if migrate:
        hookenv.log("Will perform secret backend migration.")
        set_flag("kubernetes-control-plane.secure-storage.migrate")


@when(
    "layer.vault-kv.ready",
    "kubernetes-control-plane.secure-storage.migrate",
    "kubernetes-control-plane.secure-storage.created",
)
def migrate_vault_kv_secrets_backend():
    hookenv.log("Migrating to new secrets backend.")
    local_sec = _read_encryption_secret()
    if not local_sec:
        return

    try:
        app_kv = vault_kv.VaultAppKV()
        app_kv["encryption_key"] = local_sec
        clear_flag("kubernetes-control-plane.secure-storage.migrate")
    except vault_kv.VaultNotReady:
        # will be retried because the flag kubernetes-control-plane.secure-storage.migrate remains set
        hookenv.log(
            "Failed to store application encryption_key.\n" + traceback.format_exc(),
            level=hookenv.ERROR,
        )


@when("layer.vault-kv.app-kv.set.encryption_key", "layer.vaultlocker.ready")
@when_not("kubernetes-control-plane.secure-storage.created")
def create_secure_storage():
    encryption_conf_dir = encryption_config_path().parent
    encryption_conf_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        vaultlocker.create_encrypted_loop_mount(encryption_conf_dir)
    except vaultlocker.VaultLockerError:
        # One common cause of this would be deploying on lxd.
        # Should this be more fatal?
        hookenv.log(
            "Unable to create encrypted mount for storing encryption config.\n"
            "{}".format(traceback.format_exc()),
            level=hookenv.ERROR,
        )
        set_flag("kubernetes-control-plane.secure-storage.failed")
        clear_flag("kubernetes-control-plane.secure-storage.created")
    else:
        # TODO: If Vault isn't available, it's probably still better to encrypt
        # anyway and store the key in plaintext and leadership than to just
        # give up on encryption entirely.
        if _write_encryption_config():
            # prevent an unnecessary service restart on this
            # unit since we've already handled the change
            clear_flag("layer.vault-kv.app-kv.changed.encryption_key")
            # mark secure storage as ready
            set_flag("kubernetes-control-plane.secure-storage.created")
            clear_flag("kubernetes-control-plane.secure-storage.failed")
            # restart to regen config
            clear_flag("kubernetes-control-plane.apiserver.configured")
        else:
            # encountered a failure setting up secure-storage
            set_flag("kubernetes-control-plane.secure-storage.failed")
            clear_flag("kubernetes-control-plane.secure-storage.created")


@when_not("layer.vaultlocker.ready")
@when("kubernetes-control-plane.secure-storage.created")
def revert_secure_storage():
    clear_flag("kubernetes-control-plane.secure-storage.created")
    clear_flag("kubernetes-control-plane.secure-storage.failed")
    clear_flag("kubernetes-control-plane.apiserver.configured")


@when("leadership.is_leader", "layer.vault-kv.ready")
@when_not("layer.vault-kv.app-kv.set.encryption_key")
def generate_encryption_key():
    try:
        app_kv = vault_kv.VaultAppKV()
        app_kv["encryption_key"] = kubernetes_control_plane.token_generator(32)
    except vault_kv.VaultNotReady:
        # will be retried because the flag layer.vault-kv.app-kv.set.encryption_key remains unset
        hookenv.log(
            "Failed to store application encryption_key.\n" + traceback.format_exc(),
            level=hookenv.ERROR,
        )


@when(
    "layer.vault-kv.app-kv.changed.encryption_key",
    "kubernetes-control-plane.secure-storage.created",
)
def restart_apiserver_for_encryption_key():
    clear_flag("kubernetes-control-plane.apiserver.configured")
    clear_flag("layer.vault-kv.app-kv.changed.encryption_key")


def _read_encryption_secret() -> Optional[str]:
    config = _read_encryption_config()
    if not config:
        hookenv.log("Failed to read encryption_key file.", level=hookenv.ERROR)
        return
    try:
        b64_secret = config["resources"][0]["providers"][0]["aescbc"]["keys"][0][
            "secret"
        ]
        return base64.b64decode(b64_secret).decode("utf8")
    except (KeyError, IndexError, ValueError):
        hookenv.log(
            "Failed to read and decode encryption_key secret.\n"
            + traceback.format_exc(),
            level=hookenv.ERROR,
        )
        return


def _read_encryption_config() -> Optional[Mapping]:
    enc_path = encryption_config_path()
    if enc_path.exists():
        return yaml.safe_load(enc_path.read_text())


def _write_encryption_config():
    try:
        app_kv = vault_kv.VaultAppKV()
        secret = app_kv["encryption_key"]
    except vault_kv.VaultNotReady:
        hookenv.log(
            "Failed to retrieve application encryption_key.\n" + traceback.format_exc(),
            level=hookenv.ERROR,
        )
        return False
    secret = base64.b64encode(secret.encode("utf8")).decode("utf8")
    encryption_config_path().parent.mkdir(parents=True, exist_ok=True)
    host.write_file(
        path=str(encryption_config_path()),
        perms=0o600,
        content=yaml.safe_dump(
            {
                "kind": "EncryptionConfig",
                "apiVersion": "v1",
                "resources": [
                    {
                        "resources": ["secrets"],
                        "providers": [
                            {
                                "aescbc": {
                                    "keys": [
                                        {
                                            "name": "key1",
                                            "secret": secret,
                                        }
                                    ],
                                }
                            },
                            {"identity": {}},
                        ],
                    }
                ],
            }
        ),
    )
    return True


@when_any("config.changed.pod-security-policy")
def pod_security_policy_config_changed():
    clear_flag("kubernetes-control-plane.pod-security-policy.applied")


@when_any("config.changed.ha-cluster-vip", "config.changed.ha-cluster-dns")
def haconfig_changed():
    clear_flag("hacluster-configured")


@when("ha.connected", "kubernetes-control-plane.components.started")
@when_not("hacluster-configured")
def configure_hacluster():
    # get a new cert
    if is_flag_set("certificates.available"):
        send_data()
    # update workers
    if is_flag_set("kube-control.connected"):
        send_api_urls()
    if is_flag_set("kube-api-endpoint.available"):
        push_service_data()

    set_flag("hacluster-configured")


@when_not("ha.connected")
@when("hacluster-configured")
def remove_hacluster():
    # get a new cert
    if is_flag_set("certificates.available"):
        send_data()
    # update workers
    if is_flag_set("kube-control.connected"):
        send_api_urls()
    if is_flag_set("kube-api-endpoint.available"):
        push_service_data()

    clear_flag("hacluster-configured")


class InvalidDnsProvider(Exception):
    def __init__(self, value):
        self.value = value


def get_dns_provider():
    valid_dns_providers = ["auto", "core-dns", "none"]

    dns_provider = hookenv.config("dns-provider").lower()
    if dns_provider not in valid_dns_providers:
        raise InvalidDnsProvider(dns_provider)

    if dns_provider == "auto":
        dns_provider = leader_get("auto_dns_provider")
        # On new deployments, the first time this is called, auto_dns_provider
        # hasn't been set yet. We need to make a choice now.
        if not dns_provider:
            dns_provider = "core-dns"

    # LP: 1833089. Followers end up here when setting final status; ensure only
    # leaders call leader_set.
    if is_state("leadership.is_leader"):
        leader_set(auto_dns_provider=dns_provider)
    return dns_provider


@when("endpoint.container-runtime.available")
@when_not("kubernetes-control-plane.sent-registry")
def configure_registry_location():
    registry_location = hookenv.config("image-registry")

    # Construct and send the sandbox image (pause container) to our runtime
    uri = get_sandbox_image_uri(registry_location)
    runtime = endpoint_from_flag("endpoint.container-runtime.available")
    runtime.set_config(sandbox_image=uri)
    set_flag("kubernetes-control-plane.sent-registry")


@when_any("kube-control.connected", "config.changed.image-registry")
def send_registry_location():
    """Hook to update all relations when a new dependant joins."""
    kube_control = endpoint_from_flag("kube-control.connected")
    if not kube_control:
        hookenv.log("kube-control relation currently unavailable, will be retried")
        return

    registry_location = hookenv.config("image-registry")
    # Send registry to workers
    kube_control.set_registry_location(registry_location)


@when_any("kube-control.connected", "config.changed.register-with-taints")
def set_controller_taints():
    kube_control = endpoint_from_flag("kube-control.connected")
    if not kube_control:
        hookenv.log("kube-control relation currently unavailable, will be retried")
        return

    # Send controller taints to workers
    taints = hookenv.config("register-with-taints").split()
    try:
        kube_control.set_controller_taints(taints)
    except kube_control.DecodeError as e:
        msg = "Incorrect taint format in register-with-taints"
        hookenv.log(f"{msg}: {e}")
        hookenv.status_set("blocked", msg)
        return


@when_any("kube-control.connected", "config.changed.labels")
def set_controller_labels():
    kube_control = endpoint_from_flag("kube-control.connected")
    if not kube_control:
        hookenv.log("kube-control relation currently unavailable, will be retried")
        return

    # Send controller labels to workers
    labels = hookenv.config("labels").split()
    try:
        kube_control.set_controller_labels(labels)
    except kube_control.DecodeError as e:
        msg = "Incorrect label format in labels"
        hookenv.log(f"{msg}: {e}")
        hookenv.status_set("blocked", msg)
        return


@when(
    "leadership.is_leader",
    "leadership.set.kubernetes-master-addons-restart-for-ca",
    "kubernetes-control-plane.components.started",
)
def restart_addons_for_ca():
    try:
        # Get deployments/daemonsets/statefulsets
        output = kubectl(
            "get",
            "daemonset,deployment,statefulset",
            "-o",
            "json",
            "--all-namespaces",
            "-l",
            "cdk-restart-on-ca-change=true",
        ).decode("UTF-8")
        deployments = json.loads(output)["items"]

        # Get ServiceAccounts
        service_account_names = set(
            (
                deployment["metadata"]["namespace"],
                deployment["spec"]["template"]["spec"].get(
                    "serviceAccountName", "default"
                ),
            )
            for deployment in deployments
        )
        service_accounts = []
        for namespace, name in service_account_names:
            output = kubectl(
                "get", "ServiceAccount", name, "-o", "json", "-n", namespace
            ).decode("UTF-8")
            service_account = json.loads(output)
            service_accounts.append(service_account)

        # Get ServiceAccount secrets
        secret_names = set()
        for service_account in service_accounts:
            namespace = service_account["metadata"]["namespace"]
            for secret in service_account["secrets"]:
                secret_names.add((namespace, secret["name"]))
        secrets = []
        for namespace, name in secret_names:
            output = kubectl(
                "get", "Secret", name, "-o", "json", "-n", namespace
            ).decode("UTF-8")
            secret = json.loads(output)
            secrets.append(secret)

        # Check secrets have updated CA
        with open(ca_crt_path, "rb") as f:
            ca = f.read()
        encoded_ca = base64.b64encode(ca).decode("UTF-8")
        mismatched_secrets = [
            secret for secret in secrets if secret["data"]["ca.crt"] != encoded_ca
        ]
        if mismatched_secrets:
            hookenv.log(
                "ServiceAccount secrets do not have correct ca.crt: "
                + ",".join(secret["metadata"]["name"] for secret in mismatched_secrets)
            )
            hookenv.log("Waiting to retry restarting addons")
            return

        # Now restart the addons
        for deployment in deployments:
            kind = deployment["kind"]
            namespace = deployment["metadata"]["namespace"]
            name = deployment["metadata"]["name"]
            hookenv.log("Restarting addon: %s %s %s" % (kind, namespace, name))
            kubectl("rollout", "restart", kind + "/" + name, "-n", namespace)

        leader_set({"kubernetes-master-addons-restart-for-ca": None})
    except Exception:
        hookenv.log(traceback.format_exc())
        hookenv.log("Waiting to retry restarting addons")


def add_systemd_iptables_patch():
    source = "templates/kube-proxy-iptables-fix.sh"
    dest = "/usr/local/bin/kube-proxy-iptables-fix.sh"
    copyfile(source, dest)
    os.chmod(dest, 0o775)

    template = "templates/service-iptables-fix.service"
    dest_dir = "/etc/systemd/system"
    os.makedirs(dest_dir, exist_ok=True)
    service_name = "kube-proxy-iptables-fix.service"
    copyfile(template, "{}/{}".format(dest_dir, service_name))

    check_call(["systemctl", "daemon-reload"])

    # enable and run the service
    service_resume(service_name)


@when(
    "leadership.is_leader",
    "kubernetes-control-plane.components.started",
    "endpoint.prometheus.joined",
    "certificates.ca.available",
)
def register_prometheus_jobs():
    prometheus = endpoint_from_flag("endpoint.prometheus.joined")
    tls = endpoint_from_flag("certificates.ca.available")
    monitoring_token = get_token("system:monitoring")

    for relation in prometheus.relations:
        endpoints = kubernetes_control_plane.get_internal_api_endpoints(relation)
        if not endpoints:
            continue
        address, port = endpoints[0]

        templates_dir = Path("templates")
        for job_file in Path("templates/prometheus").glob("*.yaml.j2"):
            prometheus.register_job(
                relation=relation,
                job_name=job_file.name.split(".")[0],
                job_data=yaml.safe_load(
                    render(
                        source=str(job_file.relative_to(templates_dir)),
                        target=None,  # don't write file, just return data
                        context={
                            "k8s_api_address": address,
                            "k8s_api_port": port,
                            "k8s_token": monitoring_token,
                        },
                    )
                ),
                ca_cert=tls.root_ca_cert,
            )


def detect_telegraf():
    # Telegraf uses the implicit juju-info relation, which makes it difficult
    # to tell if it's related. The "best" option is to look for the subordinate
    # charm on disk.
    for charm_dir in Path("/var/lib/juju/agents").glob("unit-*/charm"):
        metadata = yaml.safe_load((charm_dir / "metadata.yaml").read_text())
        if "telegraf" in metadata["name"]:
            return True
    else:
        return False


@when(
    "leadership.is_leader",
    "kubernetes-control-plane.components.started",
    "endpoint.grafana.joined",
)
def register_grafana_dashboards():
    grafana = endpoint_from_flag("endpoint.grafana.joined")

    # load conditional dashboards
    dash_dir = Path("templates/grafana/conditional")
    if is_flag_set("endpoint.prometheus.joined"):
        dashboard = (dash_dir / "prometheus.json").read_text()
        grafana.register_dashboard("prometheus", json.loads(dashboard))
    if detect_telegraf():
        dashboard = (dash_dir / "telegraf.json").read_text()
        grafana.register_dashboard("telegraf", json.loads(dashboard))

    # load automatic dashboards
    dash_dir = Path("templates/grafana/autoload")
    for dash_file in dash_dir.glob("*.json"):
        dashboard = dash_file.read_text()
        grafana.register_dashboard(dash_file.stem, json.loads(dashboard))


@when("endpoint.aws-iam.ready")
@when_not("kubernetes-control-plane.aws-iam.configured")
def enable_aws_iam_webhook():
    # if etcd isn't available yet, we'll set this up later
    # when we start the api server.
    if is_flag_set("etcd.available"):
        # call the other things we need to update
        clear_flag("kubernetes-control-plane.apiserver.configured")
        build_kubeconfig()
    set_flag("kubernetes-control-plane.aws-iam.configured")


@when("kubernetes-control-plane.components.started", "endpoint.aws-iam.available")
def api_server_started():
    aws_iam = endpoint_from_flag("endpoint.aws-iam.available")
    if aws_iam:
        aws_iam.set_api_server_status(True)


@when_not("kubernetes-control-plane.components.started")
@when("endpoint.aws-iam.available")
def api_server_stopped():
    aws_iam = endpoint_from_flag("endpoint.aws-iam.available")
    if aws_iam:
        aws_iam.set_api_server_status(False)


@when("kube-control.connected")
def send_default_cni():
    """Send the value of the default-cni config to the kube-control relation.
    This allows kubernetes-worker to use the same config value as well.
    """
    default_cni = hookenv.config("default-cni")
    kube_control = endpoint_from_flag("kube-control.connected")
    kube_control.set_default_cni(default_cni)


@when("config.changed.default-cni")
def default_cni_changed():
    remove_state("kubernetes-control-plane.components.started")


@when(
    "kubernetes-control-plane.components.started",
    "kubernetes-control-plane.apiserver.configured",
    "endpoint.container-runtime.available",
)
@when_not("kubernetes-control-plane.kubelet.configured")
def configure_kubelet():
    uid = hookenv.local_unit()
    username = "system:node:{}".format(get_node_name().lower())
    group = "system:nodes"
    token = get_token(username)
    if not token:
        setup_tokens(None, username, uid, group)
        token = get_token(username)
    if not token:
        hookenv.log(
            "Failed to create token for {}; will retry".format(username),
            hookenv.WARNING,
        )
        return
    has_xcp = has_external_cloud_provider()
    local_endpoint = kubernetes_control_plane.get_local_api_endpoint()
    local_url = kubernetes_control_plane.get_api_url(local_endpoint)
    create_kubeconfig(
        kubelet_kubeconfig_path, local_url, ca_crt_path, token=token, user="kubelet"
    )

    dns_ready, dns_ip, dns_port, dns_domain = get_dns_info()
    if not dns_ready:
        hookenv.log("DNS not ready, waiting to configure Kubelet")
        return
    dns_info = [dns_ip, dns_port, dns_domain]
    db.set("kubernetes-master.kubelet.dns-used", dns_info)

    registry = hookenv.config("image-registry")
    taints = hookenv.config("register-with-taints").split()
    kubernetes_common.configure_kubelet(
        dns_domain, dns_ip, registry, taints=taints, has_xcp=has_xcp
    )
    service_restart("snap.kubelet.daemon")
    set_state("node.label-config-required")
    set_flag("kubernetes-control-plane.kubelet.configured")


@when(
    "node.label-config-required",
    "kubernetes-control-plane.kubelet.configured",
    "kubernetes-control-plane.apiserver.configured",
    "authentication.setup",
)
def apply_node_labels():
    # Label configuration complete.
    label_maker = LabelMaker(kubeclientconfig_path)
    try:
        label_maker.apply_node_labels()
    except LabelMaker.NodeLabelError:
        return
    remove_state("node.label-config-required")


@when_any("config.changed.kubelet-extra-args", "config.changed.kubelet-extra-config")
def reconfigure_kubelet():
    # LP bug #1826833, always delete the state file when extra config changes
    # since CPU manager doesn’t support offlining and onlining of CPUs at runtime.
    cpu_manager_state = "/var/lib/kubelet/cpu_manager_state"
    if os.path.isfile(cpu_manager_state):
        hookenv.log("Removing file: " + cpu_manager_state)
        os.remove(cpu_manager_state)
    clear_flag("kubernetes-control-plane.kubelet.configured")


@when("external-cloud-provider.changed")
def handle_xcp_changes():
    """If xcp changes, reconfigure all necessary services."""
    hookenv.log("External cloud provider info has changed, reconfiguring...")
    clear_flag("kubernetes-control-plane.kubelet.configured")
    clear_flag("kubernetes-control-plane.apiserver.configured")
    _kick_controller_manager()
    clear_flag("external-cloud-provider.changed")


@when("kubernetes-control-plane.kubelet.configured")
def watch_dns_for_changes():
    dns_ready, dns_ip, dns_port, dns_domain = get_dns_info()
    dns_info = [dns_ip, dns_port, dns_domain]
    previous_dns_info = db.get("kubernetes-master.kubelet.dns-used")
    dns_changed = dns_info != previous_dns_info
    if dns_ready and dns_changed:
        hookenv.log("DNS info has changed, will reconfigure Kubelet")
        clear_flag("kubernetes-control-plane.kubelet.configured")


@when("cni.available")
@when_not("kubernetes-control-plane.default-cni.configured")
def configure_default_cni():
    default_cni = hookenv.config("default-cni")
    kubernetes_common.configure_default_cni(default_cni)
    set_flag("kubernetes-control-plane.default-cni.configured")


@when("ceph-client.available")
@when_not("kubernetes-control-plane.ceph.permissions.requested")
def request_ceph_permissions():
    ceph_client = endpoint_from_flag("ceph-client.available")
    request = ceph_client.get_current_request() or CephBrokerRq()
    # Permissions needed for Ceph CSI
    # https://github.com/ceph/ceph-csi/blob/v3.6.0/docs/capabilities.md
    permissions = [
        "mon",
        "profile rbd, allow r",
        "mds",
        "allow rw",
        "mgr",
        "allow rw",
        "osd",
        "profile rbd, allow rw tag cephfs metadata=*",
    ]
    client_name = hookenv.application_name()
    request.add_op(
        {"op": "set-key-permissions", "permissions": permissions, "client": client_name}
    )
    ceph_client.send_request_if_needed(request)
    set_flag("kubernetes-control-plane.ceph.permissions.requested")


@when_any("config.changed.image-registry", "cni.available")
def image_registry_changed():
    registry = hookenv.config("image-registry")
    # Share image-registry with cni requirers
    cni = endpoint_from_flag("cni.available")
    if cni:
        cni.set_image_registry(registry)
    else:
        hookenv.log(
            "CNI endpoint not available yet, waiting to set image registry data"
        )


HEAL_HANDLER = {
    "kube-apiserver": {
        "run": configure_apiserver,
        "clear_flags": [
            "kubernetes-control-plane.apiserver.configured",
            "kubernetes-control-plane.apiserver.running",
        ],
    },
    "kube-controller-manager": {"run": configure_controller_manager, "clear_flags": []},
    "kube-scheduler": {"run": configure_scheduler, "clear_flags": []},
    "kube-proxy": {
        "run": start_control_plane,
        "clear_flags": ["kubernetes-control-plane.components.started"],
    },
    "kubelet": {"run": reconfigure_kubelet, "clear_flags": []},
}
