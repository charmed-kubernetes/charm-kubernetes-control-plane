"""Helpers for the restart tests: systemd `InvocationID` snapshots and log counting."""

import re
from datetime import datetime, timezone

CP_APP = "kubernetes-control-plane"
WORKER_APP = "kubernetes-worker"
ETCD_APP = "etcd"

# `InvocationID` changes every time systemd starts a unit, so it counts restarts.
# (`NRestarts` does not: it only counts restarts systemd does itself.)
CP_SERVICES = [
    "snap.kube-apiserver.daemon",
    "snap.kube-controller-manager.daemon",
    "snap.kube-scheduler.daemon",
    "snap.kubelet.daemon",
    "snap.kube-proxy.daemon",
    # wokeignore:rule=master
    "cdk.master.auth-webhook",
]
WORKER_SERVICES = ["snap.kubelet.daemon", "snap.kube-proxy.daemon"]
SERVICES = {CP_APP: CP_SERVICES, WORKER_APP: WORKER_SERVICES}

_NO_CHANGE = re.compile(
    r"^unit-(?P<unit>\S+)-(?P<num>\d+): (?P<time>\d\d:\d\d:\d\d) INFO \S+ "
    r"(?P<service>\S+): no change$"
)


async def run_on_unit(ops_test, unit, script):
    rc, out, err = await ops_test.run(
        "juju", "exec", "-m", ops_test.model_full_name, "--unit", unit, "--", script
    )
    assert rc == 0, f"{unit}: {script!r} failed: {err or out}"
    return out


def units_of(ops_test, app):
    return sorted(u.name for u in ops_test.model.applications[app].units)


async def invocation_ids(ops_test):
    """Map unit -> service -> systemd InvocationID for every control-plane and worker unit."""
    ids = {}
    for app, services in SERVICES.items():
        script = "; ".join(
            f"echo {s} $(systemctl show -p InvocationID --value {s})" for s in services
        )
        for unit in units_of(ops_test, app):
            out = await run_on_unit(ops_test, unit, script)
            ids[unit] = dict(line.split() for line in out.splitlines() if line.strip())
    return ids


def restarted(before, after):
    """Map unit -> services whose InvocationID changed, for units present in both."""
    return {
        unit: sorted(s for s, i in services.items() if after[unit].get(s) != i)
        for unit, services in before.items()
        if unit in after
    }


def restarted_services(before, after):
    """Return the set of (application, service) pairs restarted on any unit."""
    return {
        (unit.rsplit("/", 1)[0], service)
        for unit, services in restarted(before, after).items()
        for service in services
    }


async def snap_revisions(ops_test):
    """Map unit -> the revision of every Kubernetes snap, to prove none was refreshed."""
    script = "snap list | awk '/^(kube|cdk)/ {print $1, $3}'"
    revisions = {}
    for app in SERVICES:
        for unit in units_of(ops_test, app):
            out = await run_on_unit(ops_test, unit, script)
            revisions[unit] = dict(line.split() for line in out.splitlines() if line.strip())
    return revisions


async def settle(ops_test, timeout=60 * 60, idle_period=60):
    """Wait until every application is active and idle for `idle_period` seconds."""
    apps = set(ops_test.model.applications) - {"opentelemetry-collector"}
    async with ops_test.fast_forward(fast_interval="30s"):
        await ops_test.model.wait_for_idle(
            apps=apps, status="active", timeout=timeout, idle_period=idle_period
        )


def utc_now():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


async def no_change_counts(ops_test, since):
    """Count the "<service>: no change" INFO lines logged since `since` (HH:MM:SS UTC).

    Returns a dict keyed by (unit, service). Counting only lines after `since` keeps the
    deploy phase out of the count; `--no-tail` makes `juju debug-log` exit.
    """
    rc, out, err = await ops_test.run(
        "juju", "debug-log", "-m", ops_test.model_full_name,
        "--replay", "--no-tail", "--utc", "--level", "INFO",
    )  # fmt: skip
    assert rc == 0, err
    counts = {}
    for line in out.splitlines():
        m = _NO_CHANGE.match(line)
        if m and m["time"] >= since:
            key = (f"{m['unit']}/{m['num']}", m["service"])
            counts[key] = counts.get(key, 0) + 1
    return counts
