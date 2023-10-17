# Copyright 2023 Canonical, Ltd.
"""Sync AlertManager rules from upstream repository."""

import os
import shutil
from urllib.error import URLError
from urllib.request import urlopen

# Configuration constants
VERSION = "v0.13.0"
SOURCE = (
    f"https://raw.githubusercontent.com/prometheus-operator/kube-prometheus/{VERSION}/manifests"
)
FILES = [
    "kubePrometheus-prometheusRule.yaml",
    "kubeStateMetrics-prometheusRule.yaml",
    "kubernetesControlPlane-prometheusRule.yaml",
]
DIR = "src/prometheus_alert_rules"


def fetch_file(source_url):
    """Fetches the file content from the given URL."""
    try:
        return urlopen(source_url).read().decode().strip()
    except URLError as e:
        print(f"Failed to fetch {source_url}. Error: {e}")
        return None


def main():
    # Ensure the target directory is clean and exists
    shutil.rmtree(DIR, ignore_errors=True)
    os.makedirs(DIR, exist_ok=True)

    for file in FILES:
        source_url = os.path.join(SOURCE, file)
        data = fetch_file(source_url)

        # Only write data if it's successfully fetched
        if data:
            print(f"Saving Rule {file}")
            with open(os.path.join(DIR, file), "w") as f:
                f.write(data)


if __name__ == "__main__":
    main()
