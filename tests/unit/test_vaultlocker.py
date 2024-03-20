from pathlib import Path
from unittest import mock

import ops
import ops.testing
import pytest
from charm import KubernetesControlPlaneCharm

import lib.vaultlocker


@pytest.fixture
def harness():
    harness = ops.testing.Harness(KubernetesControlPlaneCharm)
    try:
        harness.add_network("10.0.0.10", endpoint="vault-kv")
        yield harness
    finally:
        harness.cleanup()


def test_is_block_device():
    assert not lib.vaultlocker.is_block_device("/dev/null")
    assert lib.vaultlocker.is_block_device("/dev/loop0")


def test_is_mounted():
    assert not lib.vaultlocker.is_device_mounted("/dev/null")
    assert lib.vaultlocker.is_device_mounted("/dev/loop0")


@mock.patch("pathlib.Path.is_symlink", mock.MagicMock(return_value=False))
@mock.patch("pathlib.Path.parent", mock.MagicMock())
@mock.patch("pathlib.Path.exists")
@mock.patch("subprocess.check_output")
@mock.patch("lib.vaultlocker.shutil.move")
@pytest.mark.parametrize("exists", [True, False])
def test_install_alternative(mock_backup, mock_check_call, mock_exists, exists):
    mock_exists.return_value = exists
    lib.vaultlocker.install_alternative("abc", "def", "ghi")
    if exists:
        mock_backup.assert_called_once_with(Path("def"), "def.bak")
    else:
        mock_backup.assert_not_called()
    mock_check_call.assert_called_once_with(
        ["update-alternatives", "--force", "--install", Path("def"), "abc", "ghi", "50"]
    )


@mock.patch("subprocess.check_output")
@pytest.mark.parametrize("forced", [True, False])
@pytest.mark.parametrize("inode_sz", [0, 1024, 4096])
def test_mkfs_xfs(mock_check_call, forced, inode_sz):
    lib.vaultlocker.mkfs_xfs("abc", forced, inode_sz)
    mock_check_call.assert_called_once()
    args = mock_check_call.call_args[0][0]
    assert args[0] == "mkfs.xfs"
    if forced:
        assert "-f" in args
    if inode_sz == 1024:
        assert args[-3:-1] == ["-i", "size=1024"]
    assert args[-1] == "abc"


@mock.patch("subprocess.check_output")
@mock.patch("lib.vaultlocker.Fstab")
@pytest.mark.parametrize("persist", [True, False])
@pytest.mark.parametrize("filesystem", ["ext3", "fat32"])
def test_mount(mock_fstab, mock_check_output, persist, filesystem):
    options = mock.MagicMock()
    assert lib.vaultlocker.mount(
        "abc", "/path/fake", options=options, persist=persist, filesystem=filesystem
    )
    mock_check_output.assert_called_once_with(["mount", "-o", options, "abc", "/path/fake"])
    if persist:
        mock_fstab.add.assert_called_once_with("abc", "/path/fake", filesystem, options=options)
    else:
        mock_fstab.add.assert_not_called()


@mock.patch("lib.vault_kv.VaultKV.get_vault_config")
@mock.patch("lib.vaultlocker.VaultLocker.write_vaultlocker_conf")
@mock.patch("pathlib.Path.mkdir")
@mock.patch("shutil.copyfile")
@mock.patch("lib.vaultlocker.apt")
def test_vaultlocker_configure(
    apt, copyfile, mkdir, write_vaultlocker_conf, get_vault_config, harness
):
    harness.begin()
    harness.charm.encryption_at_rest.vaultlocker.configure()
    write_vaultlocker_conf.assert_called_once_with(get_vault_config())
    mkdir.assert_called_once()
    copyfile.assert_called_once_with(
        "templates/vaultlocker-loop@.service", "/etc/systemd/system/vaultlocker-loop@.service"
    )
    apt.update.assert_called_once_with()
    apt.add_package.assert_called_once_with("vaultlocker")


@mock.patch("pathlib.Path.mkdir")
@mock.patch("pathlib.Path.write_text")
@mock.patch("pathlib.Path.chmod")
@mock.patch("lib.vaultlocker.install_alternative")
def test_vaultlocker_write_conf(install, chmod, write_text, mkdir, harness):
    harness.begin()
    context = {
        "vault_url": "http://testme:8200",
        "role_id": "da-role",
        "secret_backend": "da-backend",
        "secret_id": "da-secret-id",
    }
    harness.charm.encryption_at_rest.vaultlocker.write_vaultlocker_conf(context)
    mkdir.assert_called_once()
    write_text.assert_called_once()
    chmod.assert_called_once()
    install.assert_called_once()


"""
Blocked by lack of storage metadata field definitions

@mock.patch("lib.vaultlocker.VaultLocker.encrypt_storage")
def test_vaultlocker_auto_encrypt(encrypt_storage, harness):
    harness.begin()
    vault_storage = ops.StorageMeta("da-id", {
        "type": "block",
        "vaultlocker-encrypt": True,
        "vaultlocker-mountbase": "/path/to/mount"
    })
    storages = {"da-id": vault_storage}
    harness.charm.meta.storages = storages
    harness.charm.encryption_at_rest.vaultlocker.auto_encrypt()
    encrypt_storage.assert_called_once_with("da-id", "/path/to/mount")


@mock.patch("lib.vaultlocker.VaultLocker.encrypt_device")
def test_vaultlocker_encrypt_storage(encrypt_device, harness):
    harness.begin()
    vault_storage = ops.StorageMeta("da-id", {
        "type": "block",
        "vaultlocker-encrypt": True,
        "vaultlocker-mountbase": "/path/to/mount"
    })
    storages = {"da-id": vault_storage}
    harness.charm.meta.storages = storages
    harness.charm.encryption_at_rest.vaultlocker.encrypt_storage("da-id", "/path/to/mount")
    encrypt_device.assert_called_once_with("da-id", "/path/to/mount")
"""


def test_vaultlocker_decrypted_device(harness):
    harness.begin()
    d = harness.charm.encryption_at_rest.vaultlocker._decrypted_device("/dev/null")
    assert d is None
    harness.charm.encryption_at_rest.vaultlocker._stored.uuids["/dev/null"] = "1234"
    d = harness.charm.encryption_at_rest.vaultlocker._decrypted_device("/dev/null")
    assert d == "/dev/mapper/crypt-1234"


@mock.patch("lib.vaultlocker.is_block_device", mock.MagicMock())
@mock.patch("lib.vaultlocker.is_device_mounted", mock.MagicMock(return_value=False))
@mock.patch("subprocess.check_output")
def test_vaultlocker_encrypt_device_no_mount(check_output, harness):
    harness.begin()
    device = "/dev/null"
    harness.charm.encryption_at_rest.vaultlocker.encrypt_device(device, uuid="test")
    check_output.assert_called_once_with(
        ["vaultlocker", "encrypt", "--uuid", "test", device], stderr=-1
    )
    assert harness.charm.encryption_at_rest.vaultlocker._stored.uuids == {device: "test"}


@mock.patch("lib.vaultlocker.is_block_device", mock.MagicMock())
@mock.patch("lib.vaultlocker.is_device_mounted", mock.MagicMock(return_value=False))
@mock.patch("pathlib.Path.mkdir", mock.MagicMock())
@mock.patch("subprocess.check_output")
@mock.patch("lib.vaultlocker.mkfs_xfs")
@mock.patch("lib.vaultlocker.mount")
def test_vaultlocker_encrypt_device_mounted(mount, mkfs_xfs, check_call, harness):
    harness.begin()
    device = "/dev/null"
    mountpoint = "/path/to/mount"
    mapped = "/dev/mapper/crypt-test"
    options = (
        "defaults,nofail,x-systemd.requires=vaultlocker-decrypt@test.service,comment=vaultlocker"
    )
    harness.charm.encryption_at_rest.vaultlocker.encrypt_device(
        device, mountpoint=mountpoint, uuid="test"
    )
    check_call.assert_called_once_with(
        ["vaultlocker", "encrypt", "--uuid", "test", device], stderr=-1
    )
    mkfs_xfs.assert_called_once_with(mapped)
    mount.assert_called_once_with(
        mapped, mountpoint, options=options, persist=True, filesystem="xfs"
    )
    assert harness.charm.encryption_at_rest.vaultlocker._stored.uuids == {device: "test"}


@mock.patch("pathlib.Path.mkdir", mock.MagicMock())
@mock.patch("pathlib.Path.exists", mock.MagicMock(return_value=False))
@mock.patch("pathlib.Path.write_text")
@mock.patch("lib.vaultlocker.VaultLocker.encrypt_device")
@mock.patch("subprocess.check_output")
def test_vaultlocker_create_encrypted_loop_mount(
    check_output, encrypt_device, write_text, harness
):
    harness.begin()
    mountpoint = "/path/to/mount"
    backing = Path("/var/lib/vaultlocker/backing_files/test")
    check_output.return_value = b"\n/dev/loop0\n"
    harness.charm.encryption_at_rest.vaultlocker.create_encrypted_loop_mount(
        mountpoint=mountpoint, uuid="test"
    )
    assert check_output.mock_calls == [
        mock.call(["modprobe", "loop"]),
        mock.call(["dd", "if=/dev/urandom", f"of={backing}", "bs=8M", "count=4"]),
        mock.call(["losetup", "--show", "-f", str(backing)]),
        mock.call(["systemctl", "enable", "vaultlocker-loop@test.service"]),
    ]
    encrypt_device.assert_called_once_with("/dev/loop0", "/path/to/mount", "test")
    write_text.assert_called_once_with(f"BACK_FILE={backing}\n")
