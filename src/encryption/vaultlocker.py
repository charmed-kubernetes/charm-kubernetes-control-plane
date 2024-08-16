import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional
from uuid import uuid4

import charms.operator_libs_linux.v0.apt as apt
import ops

from encryption.fstab import Fstab
from encryption.vault_kv import VaultKV, VaultNotReadyError

LOOP_ENVS = Path("/etc/vaultlocker/loop-envs")
VAULTLOCKER_CFG = """[vault]
url = {vault_url}
approle = {role_id}
backend = {secret_backend}
secret_id = {secret_id}
"""
log = logging.getLogger(__name__)


def _is_block_device(path: os.PathLike) -> bool:
    return Path(path).exists() and Path(path).is_block_device()


def _is_device_mounted(dev: os.PathLike) -> bool:
    try:
        out = subprocess.check_output(["/usr/bin/lsblk", "-P", dev]).decode()
    except subprocess.CalledProcessError:
        return False
    return bool(re.search(r'MOUNTPOINTS=".+"', out))


def _vaultlocker_exec(*args):
    """Execute vaultlocker command in an isolated environment.

    Run without the PYTHONPATH env so that any pip packages in the charm
    don't influence vaultlocker's python paths.
    """
    restore = {e: v for e in ["PYTHONPATH"] if (v := os.environ.pop(e, None))}

    try:
        subprocess.check_output(["/usr/bin/vaultlocker", *args], stderr=subprocess.PIPE)
    finally:
        os.environ.update(**restore)


def _install_alternative(name: str, target: os.PathLike, source: os.PathLike, priority: int = 50):
    """Install alternative configuration."""
    target = Path(target)
    if target.exists() and not target.is_symlink():
        # Move existing file/directory away before installing
        shutil.move(target, "{}.bak".format(target))
    target.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "/usr/bin/update-alternatives",
        "--force",
        "--install",
        target,
        name,
        source,
        str(priority),
    ]
    subprocess.check_output(cmd)


def _mkfs_xfs(device: os.PathLike, force: bool = False, inode_size: Optional[int] = None):
    """Format device with XFS filesystem.

    By default this should fail if the device already has a filesystem on it.
    :param device: Full path to device to format
    :param force: Force operation
    :param inode_size: XFS inode size in bytes; if set to 0 or None,
        the value used will be the XFS system default
    """
    cmd = ["/usr/sbin/mkfs.xfs"]
    if force:
        cmd.append("-f")

    if inode_size:
        if inode_size >= 256 and inode_size <= 2048:
            cmd += ["-i", "size={}".format(inode_size)]
        else:
            log.warning(
                "Config value xfs-inode-size=%s is invalid. Using system default.", inode_size
            )
    else:
        log.info("Using XFS filesystem with system default inode size.")

    cmd += [device]
    subprocess.check_output(cmd)


def mount(
    device: os.PathLike,
    mountpoint: os.PathLike,
    options: Optional[str] = None,
    persist: bool = False,
    filesystem: str = "ext3",
):
    """Mount a filesystem at a particular mountpoint."""
    cmd_args = ["/usr/bin/mount"]
    if options is not None:
        cmd_args.extend(["-o", options])
    cmd_args.extend([device, mountpoint])
    try:
        subprocess.check_output(cmd_args)
    except subprocess.CalledProcessError:
        log.exception("Error mounting %s at %s", device, mountpoint)
        return False

    if persist:
        return Fstab.add(device, mountpoint, filesystem, options=options)
    return True


class VaultLockerError(Exception):
    """Wrapper for exceptions raised when configuring VaultLocker."""


class VaultLocker(ops.Object):
    """Manage installation and configuration of vaultlocker, used to make encrypted drives."""

    _stored = ops.StoredState()

    def __init__(self, charm: ops.CharmBase, vault_kv: VaultKV):
        super().__init__(charm, "layer.vaultlocker")
        self.charm = charm
        self.vault_kv = vault_kv
        self._stored.set_default(uuids={})
        self.framework.observe(vault_kv.new_config, self.configure)

    def configure(self, _: ops.EventBase = None):
        """Write VaultLocker config file."""
        try:
            apt.update()
            apt.add_package("vaultlocker")
        except (apt.PackageNotFoundError, apt.PackageError):
            logging.exception("Failed to install vaultlocker")

        try:
            self.write_vaultlocker_conf(self.vault_kv.get_vault_config())
        except VaultNotReadyError:
            log.error("Failed to retrieve vault configuration.")
            raise

        # create location for loop device service envs
        LOOP_ENVS.mkdir(parents=True, exist_ok=True)
        # create loop device service template
        shutil.copyfile(
            "templates/vaultlocker-loop@.service", "/etc/systemd/system/vaultlocker-loop@.service"
        )

    def write_vaultlocker_conf(self, context: dict, prio: int = 100):
        """Write vaultlocker configuration to disk and install alternative.

        :param context: Dict of data from vault-kv relation
        :param priority: Priority of alternative configuration
        """
        vl = Path(f"/var/lib/charm/{self.charm.app.name}/vaultlocker.conf")
        vl.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        vl.write_text(VAULTLOCKER_CFG.format(**context))
        vl.chmod(0o600)
        _install_alternative("vaultlocker.conf", "/etc/vaultlocker/vaultlocker.conf", vl, prio)

    """
    A feature supporting auto encrypting juju storage was not ported
    to ops because they require adjustments to the StorageMeta fields which are
    not defined by ops.StorageMeta or even documented https://juju.is/docs/sdk/storage

    the fields "vaultlocker-encrypt" and "vaultlocker-mountbase" fields of
    a storage metadata item are undefined and therefore this feature
    is locked to reactive charms.

    the method auto_encrypt(self) originated in [layer/vaultlocker](https://github.com/juju-solutions/layer-vaultlocker/blob/2c4c16cd9e4254494d79aac1d17eacf1620d1b0f/reactive/vaultlocker.py#L41-L49)
    the method encrypt_storage(self, ...) originated in [lib.vaultlocker](https://github.com/juju-solutions/layer-vaultlocker/blob/2c4c16cd9e4254494d79aac1d17eacf1620d1b0f/lib/charms/layer/vaultlocker.py#L32-L67)
    """

    def _encrypt_device(self, device, mountpoint=None, uuid=None):
        """Set up encryption for the given block device.

        Optionally create and mount an XFS filesystem on the encrypted device.

        If ``mountpoint`` is not given, the device will not be formatted or
        mounted.  When interacting with or mounting the device manually, the
        name returned by :func:`decrypted_device` called on the device name
        should be used in place of the raw device name.
        """
        if not _is_block_device(device):
            raise VaultLockerError(f"Cannot encrypt non-block device: {device}")
        if _is_device_mounted(device):
            raise VaultLockerError(f"Cannot encrypt mounted device: {device}")
        log.info("Encrypting device: %s", device)
        if uuid is None:
            uuid = str(uuid4())
        try:
            _vaultlocker_exec("encrypt", "--uuid", uuid, device)
            self._stored.uuids[device] = uuid
            if mountpoint:
                mapped_device = f"/dev/mapper/crypt-{uuid}"
                log.info("Creating filesystem on %s (%s)", mapped_device, device)
                # If this fails, it's probably due to the size of the loopback
                # backing file that is defined by the `dd`.
                _mkfs_xfs(mapped_device)
                Path(mountpoint).mkdir(mode=0o755, parents=True, exist_ok=True)
                log.info(
                    "Mounting filesystem for %s (%s) at %s", mapped_device, device, mountpoint
                )
                fs_opts = [
                    "defaults",
                    "nofail",
                    f"x-systemd.requires=vaultlocker-decrypt@{uuid}.service",
                    "comment=vaultlocker",
                ]
                mount(
                    mapped_device,
                    mountpoint,
                    options=",".join(fs_opts),
                    persist=True,
                    filesystem="xfs",
                )
        except (subprocess.CalledProcessError, OSError) as e:
            raise VaultLockerError("Error configuring VaultLocker") from e

    def create_encrypted_loop_mount(self, mountpoint, uuid=None, backing_file=None):
        """Create a persistent loop device, encrypted, formatted to XFS, and mounted.

        A backing file will be created under `/var/lib/vaultlocker/backing_files`,
        in a UUID named file

        The `backing_file` parameter can be used to change the location where the
        backing file is created.
        """
        uuid = uuid or str(uuid4())
        if backing_file is None:
            backing_file = Path("/var/lib/vaultlocker/backing_files") / uuid
            backing_file.parent.mkdir(parents=True, exist_ok=True)
        else:
            backing_file = Path(backing_file)
            if backing_file.exists():
                raise VaultLockerError("Backing file already exists: {}", backing_file)

        try:
            # ensure loop devices are enabled
            subprocess.check_output(["/usr/sbin/modprobe", "loop"])
            # create the backing file filled with random data
            subprocess.check_output(
                ["/usr/bin/dd", "if=/dev/urandom", f"of={backing_file}", "bs=8M", "count=4"]
            )
            # claim an unused loop device
            output = subprocess.check_output(["/usr/sbin/losetup", "--show", "-f", backing_file])
            device_name = output.decode("utf8").strip()
            # encrypt the new loop device
            self._encrypt_device(device_name, mountpoint, uuid)
            # setup the service to ensure loop device is restored after reboot
            (LOOP_ENVS / uuid).write_text(f"BACK_FILE={backing_file}\n")
            subprocess.check_output(
                ["/usr/bin/systemctl", "enable", "vaultlocker-loop@{}.service".format(uuid)]
            )
        except (subprocess.CalledProcessError, OSError) as e:
            raise VaultLockerError("Error configuring VaultLocker") from e
