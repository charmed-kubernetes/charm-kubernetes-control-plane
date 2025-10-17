import contextlib
import dataclasses
import json
import logging
import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import ops
from charmhelpers.fetch.archiveurl import ArchiveUrlFetchHandler

log = logging.getLogger(__name__)

BENCH_HOME = Path("/home/ubuntu/kube-bench")
BENCH_BIN = BENCH_HOME / "kube-bench"
BENCH_CFG = BENCH_HOME / "cfg-ck"
GO_PKG = "github.com/aquasecurity/kube-bench"
RESULTS_DIR = "/home/ubuntu/kube-bench-results"


@dataclasses.dataclass
class Remedy:
    """Remedy class for benchmarking.

    Remediation dicts associate a failing test with a Remedy to fix it.
    Conservative fixes will probably leave the cluster in a good state.
    Dangerous fixes will likely break the cluster.
    Tuple examples:
    ```
      {'1.2.3': Remedy('manual -- we don't know how to auto fix this', None, None)}
      {'1.2.3': Remedy('cli', 'command to run', None)}
      {'1.2.3': Remedy('kv', 'snap', {cfg_key: value})}
    ```
    """

    type: str
    command: Optional[str]
    config: Optional[dict] = None

    def run(self, test_num: int, test_remediation: str) -> int:
        """Run the remedy command."""
        if self.type == "manual":
            log.info(
                "Test %s: unable to auto-apply remedy.\nManual steps:\n%s",
                test_num,
                test_remediation,
            )
        elif self.type == "cli":
            cmd = shlex.split(self.command)
            try:
                out = subprocess.check_output(cmd)
            except subprocess.CalledProcessError as e:
                log.error("Test %s: failed to run: %s\nError: %s", test_num, e.cmd, e.output)
                raise ActionError(f"Test {test_num}: failed to run: {e.cmd}\nError: {e.output}")
            else:
                log.info("Test %s: applied remedy: %s\nOutput: %s", test_num, cmd, out)
            return 1


CONSERVATIVE = {
    "0.0.0": Remedy("cli", 'echo "this is fine"', None),
    # etcd (no known failures with a default install)
    # k8s-control-plane (no known failures with a default install)
    # k8s-worker (no known failures with a default install)
}
ADMISSION_PLUGINS = {
    "enable-admission-plugins": (
        "AlwaysPullImages",
        "DenyServiceExternalIPs",
        "NodeRestriction",
    )
}
DANGEROUS = {
    "0.0.0": Remedy("cli", 'echo "this is fine"', None),
    # etcd (no known warnings with a default install)
    # k8s-control-plane
    "1.1.1": Remedy("cli", "chmod 600 /var/snap/kube-*/current/args", None),
    "1.1.5": Remedy("cli", "chmod 600 /root/cdk/kube-scheduler-config.yaml", None),
    "1.1.15": Remedy("cli", "chmod 600 /root/cdk/kubeschedulerconfig", None),
    "1.1.17": Remedy("cli", "chmod 600 /root/cdk/kubecontrollermanagerconfig", None),
    "1.1.20": Remedy("cli", "chmod -R 600 /root/cdk/*.crt", None),
    "1.1.21": Remedy("cli", "chmod -R 600 /root/cdk/*.key", None),
    "1.2.9": Remedy("manual", None, None),
    "1.2.11": Remedy("kv", "kube-apiserver", ADMISSION_PLUGINS),
    "1.2.25": Remedy("manual", None, None),
    "1.2.33": Remedy("manual", None, None),
    "1.2.34": Remedy("manual", None, None),
    # k8s-worker
    "4.2.9": Remedy("kv", "kubelet", {"event-qps": 0}),
    "4.2.13": Remedy(
        "kv",
        "kubelet",
        {
            "tls-cipher-suites": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,"
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,"
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,"
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,"
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,"
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,"
            "TLS_RSA_WITH_AES_256_GCM_SHA384,"
            "TLS_RSA_WITH_AES_128_GCM_SHA256"
        },
    ),
}


class ActionError(Exception):
    """Exception raised when an action fails."""


@contextlib.contextmanager
def _action_handler(event: ops.ActionEvent):
    """Context manager to handle action events."""
    try:
        yield event
    except ActionError as e:
        event.fail(str(e))


def _move_matching_parent(dirpath, filename, dest):
    """Move a parent directory that contains a specific file.

    Helper function that walks a directory looking for a given file. If found,
    the file's parent directory is moved to the given destination.

    :param: dirpath: String path to search
    :param: filename: String file to find
    :param: dest: String destination of the found parent directory
    """
    for root, _, files in os.walk(dirpath):
        for name in files:
            if name == filename:
                log.info("Moving %s to %s", root, dest)
                shutil.move(root, dest)
                return
    else:
        raise ActionError(f"Could not find {filename} in {dirpath}")


class CISBenchmark(ops.Object):
    """Action class for CIS benchmarking."""

    stored = ops.StoredState()

    def __init__(self, charm: ops.CharmBase):
        super().__init__(charm, "cis-benchmark")
        self.charm = charm
        self.framework.observe(charm.on.cis_benchmark_action, self._on_cis_benchmark)
        self.stored.set_default(service_args={})

    def _restart_charm(self, event: ops.ActionEvent):
        """Set charm-specific flags and call reactive.main()."""
        log.info("Reconcile charm")
        self.charm.reconciler.reconcile(event)

    def install(self, release, config):
        """Install kube-bench and related configuration.

        Release and configuration are set via action params. If installing an
        upstream release, this method will also install 'go' if needed.

        :param: release: Archive URI or 'upstream'
        :param: config: Archive URI of configuration files
        """
        if BENCH_HOME.exists():
            shutil.rmtree(BENCH_HOME)
        fetcher = ArchiveUrlFetchHandler()

        if release == "upstream":
            BENCH_HOME.mkdir(parents=True, exist_ok=True)

            # Setup the 'go' environment
            env = os.environ.copy()
            go_bin = shutil.which("go", path=f"{env['PATH']}:/snap/bin")
            if not go_bin:
                try:
                    cmd = ["snap", "install", "go", "--channel=stable", "--classic"]
                    subprocess.check_call(cmd)
                    go_bin = "/snap/bin/go"
                except subprocess.CalledProcessError:
                    raise ActionError("Failed to install 'go' snap")
            go_cache = os.getenv("GOCACHE", "/var/snap/go/common/cache")
            go_path = os.getenv("GOPATH", "/var/snap/go/common")
            env["GOCACHE"] = go_cache
            env["GOPATH"] = go_path
            Path(go_path).mkdir(parents=True, exist_ok=True)

            # From https://github.com/aquasecurity/kube-bench#installing-from-sources
            go_cmd = [go_bin, "get", GO_PKG, "github.com/golang/dep/cmd/dep"]
            try:
                subprocess.check_call(go_cmd, cwd=go_path, env=env)
            except subprocess.CalledProcessError:
                raise ActionError(f"Failed to run: {go_cmd}")

            go_cmd = [go_bin, "build", "-o", BENCH_BIN, f"{go_path}/src/{GO_PKG}"]
            try:
                subprocess.check_call(go_cmd, cwd=go_path, env=env)
            except subprocess.CalledProcessError:
                raise ActionError(f"Failed to run: {go_cmd}")
        else:
            # Fetch the release URI and put it in the right place.
            archive_path = fetcher.install(source=release)
            # NB: We may not know the structure of the archive, but we know the
            # directory containing 'kube-bench' belongs in our BENCH_HOME.
            _move_matching_parent(dirpath=archive_path, filename="kube-bench", dest=BENCH_HOME)

        # Fetch the config URI and put it in the right place.
        archive_dir = fetcher.install(source=config)
        # NB: We may not know the structure of the archive, but we know the
        # directory containing 'config.yaml' belongs in our BENCH_CFG.
        _move_matching_parent(dirpath=archive_dir, filename="config.yaml", dest=BENCH_CFG)

    def apply(self, event: ops.ActionEvent, remediations=None):
        """Apply remediations to address benchmark failures.

        :param: remediations: either 'conservative' or 'dangerous'
        """
        applied_fixes = 0
        danger = True if remediations == "dangerous" else False

        json_log = self.report(event, log_format="json")
        log.info("Loading JSON from: %s", json_log)
        try:
            with open(json_log, "r") as f:
                full_json: dict = json.load(f)
        except Exception:
            raise ActionError(f"Failed to load: {json_log}")

        full_json = full_json.get("Controls")[0] if "Controls" in full_json else full_json
        for test in full_json.get("tests", {}):
            for result in test.get("results", {}):
                test_num = result.get("test_number")
                test_remediation = result.get("remediation")
                test_status = result.get("status", "")

                if test_status.lower() in ("fail", "warn"):
                    test_remedy = CONSERVATIVE.get(test_num)
                    if not test_remedy and danger:
                        # no conservative remedy, check dangerous if user wants
                        test_remedy = DANGEROUS.get(test_num)
                    if test_remedy and test_remedy.type in ["cli", "manual"]:
                        applied_fixes += test_remedy.run(test_num, test_remediation)
                    elif test_remedy and test_remedy.type == "kv":
                        cfg = self.stored.service_args.get(test_remedy.command, {})
                        cfg.update(test_remedy.config)
                        self.stored.service_args[test_remedy.command] = cfg

                        log.info("Test %s: updated configuration: %s", test_num, cfg)
                        applied_fixes += 1
                    else:
                        log.info("Test %s: remediation is missing", test_num)

        # CLI and KV changes will require a charm restart; do it.
        if applied_fixes > 0:
            self._restart_charm(event)

        msg = f'Applied {applied_fixes} remediations. Re-run with "apply=none" to generate a new report.'
        event.set_results({"summary": msg})

    def reset(self, event: ops.ActionEvent):
        """Reset any remediations we applied to storedstate.

        This action does not track individual remediations to reset. Therefore,
        this function unconditionally unsets all 'cis-' prefixed arguments that
        this action may have set and restarts the relevant charm.
        """
        self.stored.service_args["kube-apiserver"] = {}
        self.stored.service_args["kube-scheduler"] = {}
        self.stored.service_args["kube-controller-manager"] = {}
        self.stored.service_args["kubelet"] = {}
        self._restart_charm(event)

        event.set_results(
            {"summary": ('Reset is complete. Re-run with "apply=none" to generate a new report.')}
        )

    def craft_extra_args(self, service: str, args: dict):
        """Craft a dict of extra args for a given service."""
        cis_args = self.stored.service_args.get(service) or {}
        return dict(**args, **cis_args)

    def report(self, event: ops.ActionEvent, log_format="text"):
        """Run kube-bench and report results.

        By default, save the full plain-text results to our RESULTS_DIR and set
        action output with a summary. This function can also save full results in
        a machine-friendly json format.

        :param: log_format: String determines if output is text or json
        :returns: Path to results log
        """
        Path(RESULTS_DIR).mkdir(parents=True, exist_ok=True)

        # Node type is different depending on the charm
        app = self.charm.meta.name or "unknown"
        version = "cis-1.10"
        if "control-plane" in app:
            # must refer to this as upstream kube-bench tests do
            # wokeignore:rule=master
            target = "master"
        elif "worker" in app:
            target = "node"
        elif "etcd" in app:
            target = "etcd"
        else:
            raise ActionError(f"Unable to determine the target to benchmark: {app}")

        # Commands and log names are different depending on the format
        _cmd_base = [BENCH_BIN, "-D", BENCH_CFG, "--benchmark", version]
        if log_format == "json":
            log_prefix = "results-json-"
            verbose_cmd = _cmd_base + ["--json", "run", "--targets", target]
        else:
            log_prefix = "results-text-"
            verbose_cmd = _cmd_base + ["run", "--targets", target]
        summary_cmd = _cmd_base + ["--noremediations", "--noresults", "run", "--targets", target]

        # Store full results for future consumption
        with tempfile.NamedTemporaryFile(
            mode="w+b", prefix=log_prefix, dir=RESULTS_DIR, delete=False
        ) as res_file:
            try:
                subprocess.call(verbose_cmd, stdout=res_file, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                raise ActionError(f"Failed to run: {verbose_cmd}")
            else:
                # remember the filename for later (and make it readable, why not?)
                Path(res_file.name).chmod(0o644)
                log_file = res_file.name

        # When making a summary, we also have a verbose report. Set action output
        # so operators can see everything related to this run.
        try:
            out = subprocess.check_output(summary_cmd, universal_newlines=True)
        except subprocess.CalledProcessError:
            raise ActionError(f"Failed to run: {summary_cmd}")
        else:
            fetch_cmd = f"juju scp {self.charm.unit.name}:{log_file} ."
            event.set_results({"cmd": summary_cmd, "report": fetch_cmd, "summary": out})

        return log or None

    def _on_cis_benchmark(self, event: ops.ActionEvent):
        with _action_handler(event):
            # Validate action params
            release = event.params.get("release") or "upstream"
            config = event.params.get("config")
            if not config:
                msg = 'Missing "config" parameter'
                raise ActionError(msg)
            remediations = event.params.get("apply")
            if remediations not in ["none", "conservative", "dangerous", "reset"]:
                raise ActionError(f'Invalid "apply" parameter: {remediations}')

            # TODO: may want an option to overwrite an existing install
            if BENCH_BIN.exists() and Path(BENCH_CFG).exists():
                log.info("%s exists; skipping install", BENCH_HOME)
            else:
                log.info("Installing benchmark from: %s", release)
                self.install(release, config)

            # Reset, remediate, or report
            if remediations == "reset":
                log.info("Attempting to remove all remediations")
                self.reset(event)
            elif remediations != "none":
                log.info('Applying "%s" remediations', remediations)
                self.apply(event, remediations)
            else:
                log.info("Report only; no remediations were requested")
                self.report(event, log_format="text")
