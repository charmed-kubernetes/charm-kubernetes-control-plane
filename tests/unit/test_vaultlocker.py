import subprocess
from pathlib import Path
from unittest import mock

import ops
import ops.testing
import pytest

import encryption.vaultlocker
from charm import KubernetesControlPlaneCharm


@pytest.fixture
def harness():
    harness = ops.testing.Harness(KubernetesControlPlaneCharm)
    try:
        harness.add_network("10.0.0.10", endpoint="vault-kv")
        yield harness
    finally:
        harness.cleanup()


@pytest.fixture(scope="module")
def mock_lsblk():
    def respond_to_dev_fake(cmd):
        dev = cmd[-1]
        if dev == "/dev/fake":
            return b"""
NAME="fake" MAJ:MIN="7:98" RM="0" SIZE="7M" RO="1" TYPE="loop" MOUNTPOINTS="/mount/fake"
"""
        raise subprocess.CalledProcessError(1, cmd, f"{dev}: not a block device")

    with mock.patch("subprocess.check_output") as lsblk:
        lsblk.side_effect = respond_to_dev_fake
        yield lsblk


@mock.patch("pathlib.Path.is_block_device", mock.MagicMock(return_value=False))
def test_is_block_device():
    assert not encryption.vaultlocker._is_block_device("/dev/null")


def test_is_mounted(mock_lsblk):
    assert not encryption.vaultlocker._is_device_mounted("/dev/null")
    mock_lsblk.assert_called_once_with(["/usr/bin/lsblk", "-P", "/dev/null"])

    mock_lsblk.reset_mock()
    assert encryption.vaultlocker._is_device_mounted("/dev/fake")
    mock_lsblk.assert_called_once_with(["/usr/bin/lsblk", "-P", "/dev/fake"])


@mock.patch("pathlib.Path.is_symlink", mock.MagicMock(return_value=False))
@mock.patch("pathlib.Path.parent", mock.MagicMock())
@mock.patch("pathlib.Path.exists")
@mock.patch("subprocess.check_output")
@mock.patch("encryption.vaultlocker.shutil.move")
@pytest.mark.parametrize("exists", [True, False])
def test_install_alternative(mock_backup, mock_check_call, mock_exists, exists):
    mock_exists.return_value = exists
    encryption.vaultlocker._install_alternative("abc", "def", "ghi")
    if exists:
        mock_backup.assert_called_once_with(Path("def"), "def.bak")
    else:
        mock_backup.assert_not_called()
    mock_check_call.assert_called_once_with(
        ["/usr/bin/update-alternatives", "--force", "--install", Path("def"), "abc", "ghi", "50"]
    )


@mock.patch("subprocess.check_output")
@pytest.mark.parametrize("forced", [True, False])
def test_mkfs_ext4(mock_check_call, forced):
    encryption.vaultlocker._mkfs_ext4("abc", force=forced)
    mock_check_call.assert_called_once()
    args = mock_check_call.call_args[0][0]
    assert args[0] == "/usr/sbin/mkfs.ext4"
    if forced:
        assert "-F" in args
    assert args[-1] == "abc"


@mock.patch("subprocess.check_output")
@mock.patch("encryption.vaultlocker.Fstab")
@pytest.mark.parametrize("persist", [True, False])
@pytest.mark.parametrize("filesystem", ["ext4", "xfs"])
def test_mount(mock_fstab, mock_check_output, persist, filesystem):
    options = mock.MagicMock()
    assert encryption.vaultlocker.mount(
        "abc", "/path/fake", options=options, persist=persist, filesystem=filesystem
    )
    mock_check_output.assert_called_once_with(
        ["/usr/bin/mount", "-o", options, "abc", "/path/fake"]
    )
    if persist:
        mock_fstab.add.assert_called_once_with("abc", "/path/fake", filesystem, options=options)
    else:
        mock_fstab.add.assert_not_called()


@mock.patch("encryption.vault_kv.VaultKV.get_vault_config")
@mock.patch("encryption.vaultlocker.VaultLocker.write_vaultlocker_conf")
@mock.patch("pathlib.Path.mkdir")
@mock.patch("shutil.copyfile")
@mock.patch("encryption.vaultlocker.apt")
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
@mock.patch("encryption.vaultlocker._install_alternative")
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

@mock.patch("encryption.vaultlocker.VaultLocker.encrypt_storage")
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


@mock.patch("encryption.vaultlocker.VaultLocker._encrypt_device")
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


@mock.patch("encryption.vaultlocker._is_block_device", mock.MagicMock())
@mock.patch("encryption.vaultlocker._is_device_mounted", mock.MagicMock(return_value=False))
@mock.patch("subprocess.check_output")
def test_vaultlocker_encrypt_device_no_mount(check_output, harness):
    harness.begin()
    device = "/dev/null"
    harness.charm.encryption_at_rest.vaultlocker._encrypt_device(device, uuid="test")
    check_output.assert_called_once_with(
        ["/usr/bin/vaultlocker", "encrypt", "--uuid", "test", device], stderr=-1
    )
    assert harness.charm.encryption_at_rest.vaultlocker._stored.uuids == {device: "test"}


@mock.patch("encryption.vaultlocker._is_block_device", mock.MagicMock())
@mock.patch("encryption.vaultlocker._is_device_mounted", mock.MagicMock(return_value=False))
@mock.patch("pathlib.Path.mkdir", mock.MagicMock())
@mock.patch("subprocess.check_output")
@mock.patch("encryption.vaultlocker._mkfs_ext4")
@mock.patch("encryption.vaultlocker.mount")
def test_vaultlocker_encrypt_device_mounted(mount, _mkfs_ext4, check_call, harness):
    harness.begin()
    device = "/dev/null"
    mountpoint = "/path/to/mount"
    mapped = Path("/dev/mapper/crypt-test")
    options = (
        "defaults,nofail,x-systemd.requires=vaultlocker-decrypt@test.service,comment=vaultlocker"
    )
    harness.charm.encryption_at_rest.vaultlocker._encrypt_device(
        device, mountpoint=mountpoint, uuid="test"
    )
    check_call.assert_called_once_with(
        ["/usr/bin/vaultlocker", "encrypt", "--uuid", "test", device], stderr=-1
    )
    _mkfs_ext4.assert_called_once_with(mapped)
    mount.assert_called_once_with(
        mapped, mountpoint, options=options, persist=True, filesystem="ext4"
    )
    assert harness.charm.encryption_at_rest.vaultlocker._stored.uuids == {device: "test"}


@mock.patch("pathlib.Path.mkdir", mock.MagicMock())
@mock.patch("pathlib.Path.exists", mock.MagicMock(return_value=False))
@mock.patch("pathlib.Path.write_text")
@mock.patch("encryption.vaultlocker.VaultLocker._encrypt_device")
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
        mock.call(["/usr/sbin/modprobe", "loop"]),
        mock.call(["/usr/bin/dd", "if=/dev/urandom", f"of={backing}", "bs=8M", "count=4"]),
        mock.call(["/usr/sbin/losetup", "--show", "-f", backing]),
        mock.call(["/usr/bin/systemctl", "enable", "vaultlocker-loop@test.service"]),
    ]
    encrypt_device.assert_called_once_with("/dev/loop0", "/path/to/mount", "test")
    write_text.assert_called_once_with(f"BACK_FILE={backing}\n")
