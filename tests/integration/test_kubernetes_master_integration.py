import asyncio
import logging

import aiohttp
import pytest
import time
import yaml

CNI_AMD64_URL = "https://api.jujucharms.com/charmstore/v5/~containers/kubernetes-worker-743/resource/cni-amd64/747"  # noqa

log = logging.getLogger(__name__)


def _check_status_messages(ops_test):
    """Validate that the status messages are correct."""
    expected_messages = {
        "kubernetes-master": "Kubernetes master running.",
        "kubernetes-worker": "Kubernetes worker running.",
    }
    for app, message in expected_messages.items():
        for unit in ops_test.model.applications[app].units:
            assert unit.workload_status_message == message


async def _retrieve_url(url, target_file):
    chunk_size = 16000
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            with target_file.open("wb") as fd:
                async for chunk in resp.content.iter_chunked(chunk_size):
                    fd.write(chunk)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test):
    log.info("Retrieve CNI...")
    cni_amd64 = ops_test.tmp_path / "cni-amd64.tgz"
    await _retrieve_url(CNI_AMD64_URL, cni_amd64)

    log.info("Build Charm...")
    charm = await ops_test.build_charm(".")

    # Work around libjuju not handling local file resources by manually
    # pre-deploying the charm w/ resource via the CLI. See
    # https://github.com/juju/python-libjuju/issues/223
    log.info("Deploy Charm...")
    rc, stdout, stderr = await ops_test._run(
        "juju",
        "deploy",
        "-m",
        ops_test.model_full_name,
        charm,
        "--resource",
        f"cni-amd64={cni_amd64}",
        "--constraints",
        "cores=4 mem=4G root-disk=16G",
    )
    assert rc == 0, f"Failed to deploy with resource: {stderr or stdout}"

    bundle = ops_test.render_bundle(
        "tests/data/bundle.yaml",
        master_charm=charm,
        # cni_amd64=cni_amd64,  # This doesn't work currently
    )

    # Use CLI to deploy bundle until https://github.com/juju/python-libjuju/pull/497
    # is released.
    # await ops_test.model.deploy(bundle)
    log.info("Build Bundle...")
    retcode, stdout, stderr = await ops_test._run(
        "juju", "deploy", "-m", ops_test.model_full_name, bundle
    )
    assert retcode == 0, f"Bundle deploy failed: {(stderr or stdout).strip()}"
    log.info(stdout)
    await ops_test.model.block_until(
        lambda: "kubernetes-master" in ops_test.model.applications, timeout=60
    )

    try:
        await ops_test.model.wait_for_idle(wait_for_active=True, timeout=60 * 60)
    except asyncio.TimeoutError:
        if "kubernetes-master" not in ops_test.model.applications:
            raise
        app = ops_test.model.applications["kubernetes-master"]
        if not app.units:
            raise
        unit = app.units[0]
        if "kube-system pod" in unit.workload_status_message:
            log.debug(
                await juju_run(
                    unit, "kubectl --kubeconfig /root/.kube/config get all -A"
                )
            )
        raise
    _check_status_messages(ops_test)


async def test_kube_api_endpoint(ops_test):
    """Validate that adding the kube-api-endpoint relation works"""
    await ops_test.model.add_relation(
        "kubernetes-master:kube-api-endpoint", "kubernetes-worker:kube-api-endpoint"
    )
    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=10 * 60)
    _check_status_messages(ops_test)


async def juju_run(unit, cmd):
    result = await unit.run(cmd)
    code = result.results["Code"]
    stdout = result.results.get("Stdout")
    stderr = result.results.get("Stderr")
    assert code == "0", f"{cmd} failed ({code}): {stderr or stdout}"
    return stdout


async def test_auth_load(ops_test):
    """Verify that the auth server can handle heavy load and / or dead endpoints."""
    app = ops_test.model.applications["kubernetes-master"]
    unit = app.units[0]

    log.info("Opening auth-webhook port")
    await juju_run(unit, "open-port 5000")

    log.info("Getting internal auth address")
    auth_addr = await juju_run(unit, "network-get --ingress-address kube-api-endpoint")

    log.info("Getting admin token")
    kubeconfig = yaml.safe_load(await juju_run(unit, "cat /home/ubuntu/config"))
    valid_token = kubeconfig["users"][0]["user"]["token"]
    invalid_token = "invalid"

    log.info("Configuring custom endpoint")
    url = f"https://{auth_addr.strip()}:5000/slow-test"
    await app.set_config({"authn-webhook-endpoint": url})

    log.info("Waiting for model to settle")
    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=10 * 60)

    async def _auth_req(token, timeout=30):
        url = f"https://{unit.public_address}:5000/v1beta1"
        req = {"kind": "TokenReview", "spec": {"token": token}}
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url, json=req, timeout=timeout, verify_ssl=False
            ) as resp:
                resp_json = await resp.json()
                return resp_json["status"]["authenticated"]

    log.info("Starting 20 background slow auth requests")
    tasks = [asyncio.create_task(_auth_req(invalid_token)) for _ in range(20)]

    log.info("Waiting for slow auth requests to block")
    await asyncio.sleep(1)

    log.info("Verifying one concurrent good auth request")
    assert await _auth_req(valid_token, timeout=5)

    log.info("Waiting for slow auth requests to complete")
    assert not any(await asyncio.gather(*tasks))


async def test_pod_security_policy(ops_test, kubernetes):
    """Test the pod-security-policy config option"""
    test_psp = {
        "apiVersion": "policy/v1beta1",
        "kind": "PodSecurityPolicy",
        "metadata": {"name": "privileged"},
        "spec": {
            "privileged": False,
            "fsGroup": {"rule": "RunAsAny"},
            "runAsUser": {"rule": "RunAsAny"},
            "seLinux": {"rule": "RunAsAny"},
            "supplementalGroups": {"rule": "RunAsAny"},
            "volumes": ["*"],
        },
    }

    async def wait_for_psp(privileged):
        deadline = time.time() + 60 * 10
        while time.time() < deadline:
            psp = kubernetes.read_object(test_psp)
            if bool(psp.spec.privileged) == privileged:
                break
            await asyncio.sleep(10)
        else:
            pytest.fail("Timed out waiting for PodSecurityPolicy update")

    app = ops_test.model.applications["kubernetes-master"]

    await app.set_config({"pod-security-policy": yaml.dump(test_psp)})
    await wait_for_psp(privileged=False)

    await app.set_config({"pod-security-policy": ""})
    await wait_for_psp(privileged=True)
