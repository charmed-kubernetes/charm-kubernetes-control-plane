import logging
import os
import random
import re
import string
import tempfile
from base64 import b64decode, b64encode
from dataclasses import dataclass
from subprocess import CalledProcessError, check_call, check_output
from typing import Mapping

import charms.contextual_status as status
import yaml
from jinja2 import Environment, FileSystemLoader
from kubectl import kubectl, kubectl_get
from ops import MaintenanceStatus

auth_secret_ns = "kube-system"
auth_secret_type = "juju.is/token-auth"
auth_webhook_root = "/root/cdk/auth-webhook"
auth_webhook_conf = os.path.join(auth_webhook_root, "auth-webhook-conf.yaml")
auth_webhook_exe = os.path.join(auth_webhook_root, "auth-webhook.py")
# wokeignore:rule=master
auth_webhook_svc_name = "cdk.master.auth-webhook"
auth_webhook_svc = "/etc/systemd/system/{}.service".format(auth_webhook_svc_name)
log_dir = "/var/log/kubernetes"

log = logging.getLogger(__name__)


@dataclass
class Secret:
    """Wrap a kubectl secret."""

    secret_id: str
    password: str


def _uplift_keystone_endpoint() -> str:
    """Uplift the keystone auth service from a cdk-addons installation."""
    try:
        keystone_auth_service = kubectl_get(
            "service", "-n", "kube-system", "k8s-keystone-auth-service"
        )
    except CalledProcessError:
        log.info("No k8s-keystone-auth-service to uplift")
        return None
    labels = keystone_auth_service.get("metadata", {}).get("labels", {})
    if labels.get("cdk-addons") != "true":
        log.info("No cdk-addons based k8s-keystone-auth-service to uplift")
        return None
    if not (spec := keystone_auth_service.get("spec")):
        log.error("No spec found for k8s-keystone-auth-service")
        return None
    cluster_ip, port = spec.get("clusterIP"), spec.get("ports")[0].get("port")
    if not cluster_ip or not port:
        log.error("No clusterIP or port found for k8s-keystone-auth-service")
        return None
    return f"https://{cluster_ip}:{port}/webhook"


def _uplift_aws_iam_endpoint() -> str:
    return None


def configure(charm_dir, custom_authn_endpoint=None):
    """Render auth webhook templates and start the related service."""
    status.add(MaintenanceStatus("Configuring auth webhook"))
    keystone_endpoint = _uplift_keystone_endpoint()
    aws_iam_endpoint = _uplift_aws_iam_endpoint()

    # Set the number of gunicorn workers based on our core count. (2*cores)+1 is
    # recommended: https://docs.gunicorn.org/en/stable/design.html#how-many-workers
    try:
        cores = int(check_output(["nproc"]).decode("utf-8").strip())
    except CalledProcessError as e:
        log.exception(e)
        log.error("Failed to determine core count for auth-webhook")
        # Our default architecture is 2-cores for k8s-cp units
        cores = 2
    else:
        # Put an upper bound on cores; more than 12ish workers is overkill
        cores = 6 if cores > 6 else cores

    # For 'api_ver', match the api version of the authentication.k8s.io TokenReview
    # that k8s-apiserver will be sending:
    #   https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.23/#tokenreview-v1-authentication-k8s-io
    context = {
        "api_ver": "v1",
        "aws_iam_endpoint": aws_iam_endpoint,
        "charm_dir": charm_dir,
        "custom_authn_endpoint": custom_authn_endpoint,
        "keystone_endpoint": keystone_endpoint,
        "logfile": "{}.log".format(auth_webhook_svc_name),
        "num_workers": cores * 2 + 1,
        "pidfile": "{}.pid".format(auth_webhook_svc_name),
        "port": 5000,
        "root_dir": auth_webhook_root,
    }

    os.makedirs(auth_webhook_root, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)

    render("auth-webhook-conf.yaml", auth_webhook_conf, context)
    render("auth-webhook.py", auth_webhook_exe, context)
    render("auth-webhook.logrotate", "/etc/logrotate.d/auth-webhook", context)
    render("auth-webhook.service", auth_webhook_svc, context)
    restart()


def delete_token(secret_id: str):
    kubectl("delete", "secret", "-n", auth_secret_ns, secret_id, "--ignore-not-found=true")


def create_token(uid, username, groups=[]):
    token = get_token(username)
    if token:
        return token

    # secret IDs must be unique and rfc1123 compliant
    sani_name = re.sub("[^0-9a-z.-]+", "-", uid.lower())
    secret_id = "auth-{}-{}".format(sani_name, generate_rfc1123(10))

    # The authenticator expects tokens to be in the form user::token
    token = "{}::{}".format(uid, token_generator())

    uid_b64 = b64encode(uid.encode("utf-8")).decode("utf-8")
    username_b64 = b64encode(username.encode("utf-8")).decode("utf-8")
    token_b64 = b64encode(token.encode("utf-8")).decode("utf-8")
    groups_b64 = b64encode(",".join(groups).encode("utf-8")).decode("utf-8")

    secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": secret_id,
            "namespace": auth_secret_ns,
        },
        "type": auth_secret_type,
        "data": {
            "uid": uid_b64,
            "username": username_b64,
            "password": token_b64,
            "groups": groups_b64,
        },
    }

    with tempfile.NamedTemporaryFile() as tmp_manifest:
        with open(tmp_manifest.name, "w") as f:
            yaml.safe_dump(secret, f)
        kubectl("apply", "-f", tmp_manifest.name)

    return token


def generate_rfc1123(length=10):
    """Generate a random string compliant with RFC 1123.

    https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-subdomain-names

    param: length - the length of the string to generate
    """
    length = 253 if length > 253 else length
    valid_chars = string.ascii_lowercase + string.digits
    rand_str = "".join(random.SystemRandom().choice(valid_chars) for _ in range(length))
    return rand_str


def get_secrets():
    """Get all the secrets that CK created."""
    output = kubectl_get(
        "secrets",
        "-n",
        auth_secret_ns,
        "--field-selector",
        "type={}".format(auth_secret_type),
    )
    secrets: Mapping[str, Secret] = {}
    for secret in output.get("items", []):
        try:
            data_b64 = secret["data"]
            password_b64 = data_b64["password"].encode("utf-8")
            username_b64 = data_b64["username"].encode("utf-8")
        except (KeyError, TypeError):
            # CK authn secrets will have populated 'data', but not all secrets do
            continue

        password = b64decode(password_b64).decode("utf-8")
        secret_user = b64decode(username_b64).decode("utf-8")
        secrets[secret_user] = Secret(secret["metadata"]["name"], password)
    return secrets


def get_token(username):
    """Get the password for the given user from the secret that CK created."""
    for secret_user, properties in get_secrets().items():
        if username == secret_user:
            return properties.password
    return None


def render(src, dest, context):
    """Read a template file, render it, and write to dest."""
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template(src)
    output = template.render(context)

    with open(dest, "w") as f:
        f.write(output)


def restart():
    """Restart the auth-webhook service."""
    check_call(["systemctl", "daemon-reload"])
    check_call(["systemctl", "restart", auth_webhook_svc_name])


def token_generator(length=32):
    """Generate a random token for use in account tokens.

    param: length - the length of the token to generate
    """
    alpha = string.ascii_letters + string.digits
    token = "".join(random.SystemRandom().choice(alpha) for _ in range(length))
    return token
