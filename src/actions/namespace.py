import os

import ops
from charmhelpers.core.templating import render
from kubectl import kubectl
from yaml import safe_load as load

os.environ["PATH"] += os.pathsep + os.path.join(os.sep, "snap", "bin")


def namespace_list(event: ops.ActionEvent):
    y = load(kubectl("get", "namespaces", "-o", "yaml"))
    ns = [i["metadata"]["name"] for i in y["items"]]
    event.set_results({"namespaces": ", ".join(ns) + "."})


def namespace_create(event: ops.ActionEvent):
    name = event.params["name"]
    if name in namespace_list():
        event.fail('Namespace "{}" already exists.'.format(name))
        return

    render(
        "create-namespace.yaml.j2",
        "/etc/kubernetes/addons/create-namespace.yaml",
        context={"name": name},
    )
    kubectl("create", "-f", "/etc/kubernetes/addons/create-namespace.yaml")
    event.set_results({"msg": 'Namespace "{}" created.'.format(name)})


def namespace_delete(event: ops.ActionEvent):
    name = event.params["name"]
    if name in ["default", "kube-system"]:
        event.fail('Not allowed to delete "{}".'.format(name))
        return
    if name not in namespace_list():
        event.fail('Namespace "{}" does not exist.'.format(name))
        return
    kubectl("delete", "ns/" + name)
    event.set_results({"msg": 'Namespace "{}" deleted.'.format(name)})
