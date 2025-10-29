# Copyright 2023 Canonical, Ltd.
"""Sync Grafana dashboards from upstream repository.

Dashboard changes:
 - Remove built-in $prometheus datasource (COS adds the datasource automatically)
"""

import json
import os
import shutil
import subprocess
from pathlib import Path
from urllib.request import urlopen

import yaml

VERSION = "v0.13.0"
SOURCE_URL = f"https://raw.githubusercontent.com/prometheus-operator/kube-prometheus/{VERSION}/manifests/grafana-dashboardDefinitions.yaml"
DASHBOARDS = {
    "apiserver.json",
    "cluster-total.json",
    "controller-manager.json",
    "k8s-resources-cluster.json",
    "k8s-resources-multicluster.json",
    "k8s-resources-namespace.json",
    "k8s-resources-node.json",
    "k8s-resources-pod.json",
    "k8s-resources-workload.json",
    "k8s-resources-workloads-namespace.json",
    "kubelet.json",
    "namespace-by-pod.json",
    "namespace-by-workload.json",
    "persistentvolumesusage.json",
    "pod-total.json",
    "proxy.json",
    "scheduler.json",
    "workload-total.json",
}
TARGET_DIR = "src/grafana_dashboards"
PATCHES_DIR = Path("scripts/dashboard-patches")


def apply_patches():
    """Apply patches to the downloaded and processed dashboard files.

    The following patches are applied to the upstream dashboards:

        001_cluster_and_juju_model: The patch adds a reference to the
            juju model on the cluster dropdowns so that they only show
            the clusters belonging to the selected juju models.
    """
    for patch_file in PATCHES_DIR.glob("*"):
        print(f"Applying patch {patch_file}")
        subprocess.check_call(["/usr/bin/git", "apply", str(patch_file)])


def fetch_dashboards(source_url):
    print(f"Fetching dashboard data from {source_url}")
    with urlopen(source_url) as request:
        return yaml.safe_load(request.read())


def process_dashboards_data(data):
    for config_map in data["items"]:
        for key, value in config_map["data"].items():
            if key not in DASHBOARDS:
                continue

            yield key, json.loads(value)


def prepare_dashboard(json_value):
    """Prepare dashboard data for COS integration."""
    # Remove the built-in Prometheus datasource
    templating_list = json_value.get("templating", {}).get("list", [])
    for item in templating_list:
        if item.get("name") == "datasource" and item.get("type") == "datasource":
            templating_list.remove(item)
            break

    # convert json value to string and perform replacement
    as_string = json.dumps(json_value, indent=4)
    return as_string.replace("$datasource", "$prometheusds")


def save_dashboard_to_file(name, data):
    filepath = os.path.join(TARGET_DIR, name)
    print(f"Saving dashboard '{name}' to {filepath}")
    with open(filepath, "w") as f:
        f.write(data)


def main():
    shutil.rmtree(TARGET_DIR, ignore_errors=True)
    os.mkdir(TARGET_DIR)

    data = fetch_dashboards(SOURCE_URL)

    for name, dashboard_data in process_dashboards_data(data):
        dashboard = prepare_dashboard(dashboard_data)
        save_dashboard_to_file(name, dashboard)
    apply_patches()


if __name__ == "__main__":
    main()
