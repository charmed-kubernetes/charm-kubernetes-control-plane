import base64
import logging
from pathlib import Path
from typing import Mapping, Optional

import ops
import yaml
from auth_webhook import token_generator
from charms import kubernetes_snaps

from lib.vault_kv import VaultKV, VaultNotReadyError
from lib.vaultlocker import VaultLocker, VaultLockerError

log = logging.getLogger(__name__)


class EncryptionAtRest(ops.Object):
    def __init__(self, charm: ops.CharmBase):
        super().__init__(charm, "encryption-at-rest")
        self.charm = charm
        self.vault_kv = VaultKV(charm)
        self.vaultlocker = VaultLocker(charm, self.vault_kv)
        self.encrypt_config = kubernetes_snaps.encryption_config_path()

    def prepare_encryption(self):
        if not self.vault_kv.requires.relations:
            return

        self.vaultlocker.prepare()
        self.create_secure_storage()
        if self.charm.unit.is_leader():
            key = self.generate_encryption_key()
            self.vault_kv.app_kv["encryption_key"] = key

    def create_secure_storage(self):
        encryption_conf_dir = self.encrypt_config.parent
        encryption_conf_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            self.vaultlocker.create_encrypted_loop_mount(encryption_conf_dir)
        except VaultLockerError:
            # One common cause of this would be deploying on lxd.
            # Should this be more fatal?
            log.exception("Unable to create encrypted mount for storing encryption config.")
            raise
        else:
            self._write_encryption_config()

    def generate_encryption_key(self) -> str:
        try:
            app_kv = self.vault_kv.app_kv
            app_kv["encryption_key"] = token_generator(32)
        except VaultNotReadyError:
            # will be retried because the flag layer.vault-kv.app-kv.set.encryption_key remains unset
            log.exception("Failed to store application encryption_key.")
            raise

    def _read_encryption_secret(self) -> Optional[str]:
        config = self._read_encryption_config()
        if not config:
            log.error("Failed to read encryption_key file.")
            raise
        try:
            b64_secret = config["resources"][0]["providers"][0]["aescbc"]["keys"][0]["secret"]
            return base64.b64decode(b64_secret).decode("utf8")
        except (KeyError, IndexError, ValueError):
            log.exception("Failed to read and decode encryption_key secret.")
            raise

    def _read_encryption_config(self) -> Optional[Mapping]:
        if self.encrypt_config.exists():
            return yaml.safe_load(self.encrypt_config.read_text())

    def _write_encryption_config(self):
        try:
            app_kv = self.vault_kv.VaultAppKV()
            secret = app_kv["encryption_key"]
        except VaultNotReadyError:
            log.exception("Failed to retrieve application encryption_key.")
            raise
        secret = base64.b64encode(secret.encode("utf8")).decode("utf8")
        template = Path("templates/encryption-config.yaml").read_text()
        config = yaml.safe_load(template)
        config["resources"][0]["providers"][0]["aescbc"]["keys"][0]["secret"] = secret

        self.encrypt_config.parent.mkdir(parents=True, exist_ok=True)
        self.encrypt_config.write_text(yaml.safe_dump(config))
        self.encrypt_config.chmod(0o600)
