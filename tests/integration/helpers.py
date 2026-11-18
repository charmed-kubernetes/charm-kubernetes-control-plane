"""Helpers for the control-plane restart tests: systemd `InvocationID` snapshots and log counts."""

import asyncio
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

# When the sole kube-apiserver restarts (~25-30s), kube-controller-manager and
# kube-scheduler lose their 10s leader-election lease, exit, and are restarted by
# systemd even when the charm logged `no change` for them.
LEASE_HOLDERS = {
    "snap.kube-controller-manager.daemon",
    "snap.kube-scheduler.daemon",
}

_DECISION = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) INFO \S+ \S+ "
    r"(?:\S+: )?(?P<service>snap\.\S+\.daemon|cdk\.\S+): (?P<reason>.+)$"
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
    """Map unit -> service -> systemd InvocationID for every control-plane unit."""
    script = "; ".join(
        f"echo {s} $(systemctl show -p InvocationID --value {s})" for s in CP_SERVICES
    )
    units = units_of(ops_test, CP_APP)
    outputs = await asyncio.gather(*(run_on_unit(ops_test, u, script) for u in units))
    return {
        unit: dict(line.split() for line in out.splitlines() if line.strip())
        for unit, out in zip(units, outputs)
    }


def restarted(before, after):
    """Map unit -> services whose InvocationID changed, for units present in both."""
    return {
        unit: sorted(s for s, i in services.items() if after[unit].get(s) != i)
        for unit, services in before.items()
        if unit in after
    }


def restarted_services(before, after):
    """Return the set of control-plane service names restarted on any control-plane unit."""
    return {service for services in restarted(before, after).values() for service in services}


async def settle(ops_test, timeout=30 * 60, idle_period=15):
    """Wait until every core application is active and idle for `idle_period` seconds."""
    apps = set(ops_test.model.applications) - {"opentelemetry-collector"}
    await ops_test.model.wait_for_idle(
        apps=apps, status="active", timeout=timeout, idle_period=idle_period
    )


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


async def service_decisions(ops_test, since):
    """Map (unit, service) -> list of restart reasons logged since `since` (UTC).

    Reads `/var/log/juju/unit-*.log` directly on each control-plane unit so there is no
    race with Juju's asynchronous `log-sender` buffer to the controller.
    """
    units = units_of(ops_test, CP_APP)
    outputs = await asyncio.gather(
        *(
            run_on_unit(
                ops_test,
                u,
                f"grep ' INFO ' /var/log/juju/unit-{u.replace('/', '-')}.log || true",
            )
            for u in units
        )
    )
    decisions = {}
    for unit, out in zip(units, outputs):
        for line in out.splitlines():
            m = _DECISION.match(line)
            if m and m["ts"] >= since:
                decisions.setdefault((unit, m["service"]), []).append(m["reason"])
    return decisions

async def no_change_counts(ops_test, since):
    """Count the `<service>: no change` INFO lines logged since `since` (HH:MM:SS UTC)."""
    decisions = await service_decisions(ops_test, since)
    return {key: sum(1 for r in reasons if r == "no change") for key, reasons in decisions.items()}


def charm_restarted_services(decisions):
    """Return the set of services the charm itself chose to restart (`reason != 'no change'`)."""
    return {
        service
        for (_, service), reasons in decisions.items()
        if any(r != "no change" for r in reasons)
    }
