import os
import tempfile

import ops
from yaml import safe_dump, safe_load

from kubectl import kubectl

os.environ["PATH"] += os.pathsep + os.path.join(os.sep, "snap", "bin")


def namespace_list(event: ops.ActionEvent):
    y = safe_load(kubectl("get", "namespaces", "-o", "yaml"))
    ns = [i["metadata"]["name"] for i in y["items"]]
    event.set_results({"namespaces": ", ".join(ns) + "."})
    return ns


def namespace_create(event: ops.ActionEvent):
    name = event.params["name"]
    if name in namespace_list(event):
        event.fail('Namespace "{}" already exists.'.format(name))
        return

    ns = {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": name, "labels": {"name": name}},
    }
    with tempfile.NamedTemporaryFile("w+") as tmp:
        tmp.write(safe_dump(ns))
        tmp.flush()
        kubectl("create", "-f", tmp.name)

    event.set_results({"msg": 'Namespace "{}" created.'.format(name)})


def namespace_delete(event: ops.ActionEvent):
    name = event.params["name"]
    if name in ["default", "kube-system"]:
        event.fail('Not allowed to delete "{}".'.format(name))
        return
    if name not in namespace_list(event):
        event.fail('Namespace "{}" does not exist.'.format(name))
        return
    kubectl("delete", "ns/" + name)
    event.set_results({"msg": 'Namespace "{}" deleted.'.format(name)})
