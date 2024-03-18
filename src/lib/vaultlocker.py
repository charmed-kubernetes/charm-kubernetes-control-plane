import logging
import os
import re
import shutil
from pathlib import Path
from subprocess import CalledProcessError, check_call, check_output
from uuid import uuid4

import ops

from lib.fstab import Fstab
from lib.vault_kv import VaultKV


LOOP_ENVS = Path("/etc/vaultlocker/loop-envs")
VAULTLOCKER_CFG = """[vault]
url = {vault_url}
approle = {role_id}
backend = {secret_backend}
secret_id = {secret_id}
"""
log = logging.getLogger(__name__)


def is_block_device(path: os.PathLike) -> bool:
    path: Path = Path(path)
    return path.exists() and path.is_block_device()


def is_device_mounted(dev: os.PathLike) -> bool:
    device: Path = Path(dev)
    try:
        out = check_output(["lsblk", "-P", device]).decode()
    except CalledProcessError:
        return False
    return bool(re.search(r'MOUNTPOINT=".+"', out))


def install_alternative(name: str, target: os.PathLike, source: os.PathLike, priority: int = 50):
    """Install alternative configuration"""
    target = Path(target)
    if target.exists() and not target.is_symlink():
        # Move existing file/directory away before installing
        shutil.move(target, "{}.bak".format(target))
    target.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["update-alternatives", "--force", "--install", target, name, source, str(priority)]
    check_call(cmd)


def mkfs_xfs(device: os.PathLike, force: bool = False, inode_size=None):
    """Format device with XFS filesystem.

    By default this should fail if the device already has a filesystem on it.
    :param device: Full path to device to format
    :ptype device: tr
    :param force: Force operation
    :ptype: force: boolean
    :param inode_size: XFS inode size in bytes; if set to 0 or None,
        the value used will be the XFS system default
    :ptype inode_size: int
    """
    cmd = ["mkfs.xfs"]
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
    check_call(cmd)


def mount(device, mountpoint, options=None, persist=False, filesystem="ext3"):
    """Mount a filesystem at a particular mountpoint"""
    cmd_args = ["mount"]
    if options is not None:
        cmd_args.extend(["-o", options])
    cmd_args.extend([device, mountpoint])
    try:
        check_output(cmd_args)
    except CalledProcessError:
        log.exception("Error mounting %s at %s", device, mountpoint)
        return False

    if persist:
        return Fstab.add(device, mountpoint, filesystem, options=options)
    return True


class VaultLockerError(Exception):
    """Wrapper for exceptions raised when configuring VaultLocker."""

    def __init__(self, msg, *args, **kwargs):
        super().__init__(msg.format(*args, **kwargs))


class VaultLocker(ops.Object):
    _stored = ops.StoredState()

    def __init__(self, charm: ops.CharmBase, vault_kv: VaultKV):
        super().__init__(charm, "layer.vaultlocker")
        self.charm = charm
        self.vault_kv = vault_kv
        self._stored.set_default(uuids={})
        self.framework.observe(vault_kv.new_config, self.configure)

    def prepare(self):
        self.apt_install()
        self.configure()
        self.auto_encrypt()

    def apt_install(self):
        check_call(["apt", "update"])
        check_call(["apt", "install", "vaultlocker"])

    def configure(self, _: ops.EventBase = None):
        # write VaultLocker config file
        self.write_vaultlocker_conf(self.vault_kv.get_vault_config())
        # create location for loop device service envs
        LOOP_ENVS.mkdir(parents=True, exist_ok=True)
        # create loop device service template
        shutil.copyfile(
            "templates/vaultlocker-loop@.service", "/etc/systemd/system/vaultlocker-loop@.service"
        )

    def write_vaultlocker_conf(self, context, priority=100):
        """Write vaultlocker configuration to disk and install alternative

        :param context: Dict of data from vault-kv relation
        :ptype: context: dict
        :param priority: Priority of alternative configuration
        :ptype: priority: int
        """
        charm_vl_path = Path(f"/var/lib/charm/{self.charm.app.name}/vaultlocker.conf")
        charm_vl_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        charm_vl_path.write_text(VAULTLOCKER_CFG.format(**context))
        charm_vl_path.chmod(0o600)
        install_alternative(
            "vaultlocker.conf", "/etc/vaultlocker/vaultlocker.conf", charm_vl_path, priority
        )

    def auto_encrypt(self):
        for id, meta in self.charm.meta.storages.items():
            if meta.get("vaultlocker-encrypt", False):
                mountbase = meta.get("vaultlocker-mountbase")
                self.encrypt_storage(id, mountbase)

    def encrypt_storage(self, storage_name, mountbase=None):
        """Set up encryption for the given Juju storage entry, and optionally create
        and mount XFS filesystems on the encrypted storage entry location(s).

        Note that the storage entry **must** be defined with ``type: block``.

        If ``mountbase`` is not given, the location(s) will not be formatted or
        mounted.  When interacting with or mounting the location(s) manually, the
        name returned by :func:`decrypted_device` called on the storage entry's
        location should be used in place of the raw location.

        If the storage is defined as ``multiple``, the individual locations
        will be mounted at ``{mountbase}/{storage_name}/{num}`` where ``{num}``
        is based on the storage ID.  Otherwise, the storage will mounted at
        ``{mountbase}/{storage_name}``.
        """
        storage_metadata = self.charm.meta.storages[storage_name]
        if storage_metadata["type"] != "block":
            raise VaultLockerError("Cannot encrypt non-block storage: {}", storage_name)
        multiple = "multiple" in storage_metadata
        for storage_meta in self.charm.meta.storages.values():
            if not storage_meta.storage_name.startswith(storage_name + "/"):
                continue
            storage_location = storage_meta.location
            if mountbase and multiple:
                mountpoint = Path(mountbase) / storage_meta.storage_name
            elif mountbase:
                mountpoint = Path(mountbase) / storage_name
            else:
                mountpoint = None
            self.encrypt_device(storage_location, mountpoint)
            # set_flag('layer.vaultlocker.{}.ready'.format(storage_meta.storage_name))
            # set_flag('layer.vaultlocker.{}.ready'.format(storage_name))

    def encrypt_device(self, device, mountpoint=None, uuid=None):
        """Set up encryption for the given block device, and optionally create and
        mount an XFS filesystem on the encrypted device.

        If ``mountpoint`` is not given, the device will not be formatted or
        mounted.  When interacting with or mounting the device manually, the
        name returned by :func:`decrypted_device` called on the device name
        should be used in place of the raw device name.
        """
        if not is_block_device(device):
            raise VaultLockerError("Cannot encrypt non-block device: {}", device)
        if is_device_mounted(device):
            raise VaultLockerError("Cannot encrypt mounted device: {}", device)
        log.info("Encrypting device: %s", device)
        if uuid is None:
            uuid = str(uuid4())
        try:
            check_call(["vaultlocker", "encrypt", "--uuid", uuid, device])
            self._stored.uuids[device] = uuid
            if mountpoint:
                mapped_device = self.decrypted_device(device)
                log.info("Creating filesystem on %s (%s)", mapped_device, device)
                # If this fails, it's probably due to the size of the loopback
                #    backing file that is defined by the `dd`.
                mkfs_xfs(mapped_device)
                Path(mountpoint).mkdir(mode=0o755, parents=True, exist_ok=True)
                log.info(
                    "Mounting filesystem for %s (%s) at %s", mapped_device, device, mountpoint
                )
                fs_opts = [
                    "defaults",
                    "nofail",
                    f"x-systemd.requires=vaultlocker-decrypt@{uuid}.service" "comment=vaultlocker",
                ]
                mount(
                    mapped_device,
                    mountpoint,
                    options=",".join(fs_opts),
                    persist=True,
                    filesystem="xfs",
                )
        except (CalledProcessError, OSError) as e:
            raise VaultLockerError("Error configuring VaultLocker") from e

    def decrypted_device(self, device):
        """Returns the mapped device name for the decrypted version of the encrypted
        device.

        This mapped device name is what should be used for mounting the device.
        """
        uuid = self._stored.uuids.get(device)
        if not uuid:
            return None
        return f"/dev/mapper/crypt-{uuid}"

    def create_encrypted_loop_mount(
        self, mount_path, block_size="1M", block_count=20, backing_file=None
    ):
        """Creates a persistent loop device, encrypts it, formats it as XFS, and
        mounts it at the given `mount_path`.

        A backing file will be created under `/var/lib/vaultlocker/backing_files`,
        in a UUID named file, according to `block_size` and `block_count`
        parameters, which map to `bs` and `count` of the `dd` command.  Note that
        the backing file must be a bit over 16M to allow for the XFS file system
        plus some additional metadata needed for the encryption.  It is not
        recommended to go below the default of 20M (20 blocks, 1M each).

        The `backing_file` parameter can be used to change the location where the
        backing file is created.
        """
        uuid = str(uuid4())
        if backing_file is None:
            backing_file = Path("/var/lib/vaultlocker/backing_files") / uuid
            backing_file.parent.mkdir(parents=True, exist_ok=True)
        else:
            backing_file = Path(backing_file)
            if backing_file.exists():
                raise VaultLockerError("Backing file already exists: {}", backing_file)

        try:
            # ensure loop devices are enabled
            check_call(["modprobe", "loop"])
            # create the backing file filled with random data
            check_call(["dd", "if=/dev/urandom", "of={}".format(backing_file), "bs=8M", "count=4"])
            # claim an unused loop device
            output = check_output(["losetup", "--show", "-f", str(backing_file)])
            device_name = output.decode("utf8").strip()
            # encrypt the new loop device
            self.encrypt_device(device_name, str(mount_path), uuid)
            # setup the service to ensure loop device is restored after reboot
            (LOOP_ENVS / uuid).write_text(
                "".join(
                    [
                        "BACK_FILE={}\n".format(backing_file),
                    ]
                )
            )
            check_call(["systemctl", "enable", "vaultlocker-loop@{}.service".format(uuid)])
        except (CalledProcessError, OSError) as e:
            raise VaultLockerError("Error configuring VaultLocker") from e
