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
ENCRYPTION_KEY = "encryption_key"


class EncryptionAtRest(ops.Object):
    """Setup control-plane encryption keys at rest stored into vault-kv."""

    def __init__(self, charm: ops.CharmBase):
        super().__init__(charm, "encryption-at-rest")
        self.charm = charm
        self.vault_kv = VaultKV(charm)
        self.vaultlocker = VaultLocker(charm, self.vault_kv)
        self.encrypt_config = kubernetes_snaps.encryption_config_path()

    def prepare(self):
        if not self.vault_kv.requires.relations:
            return

        self.vaultlocker.prepare()
        if self.charm.unit.is_leader():
            self._generate_encryption_key()
        self._write_encryption_config()

    def _generate_encryption_key(self) -> str:
        try:
            app_kv = self.vault_kv.app_kv
            if ENCRYPTION_KEY not in app_kv:
                app_kv[ENCRYPTION_KEY] = token_generator(32)
        except VaultNotReadyError:
            log.exception("Failed to store application encryption_key.")
            raise

    def _read_encryption_config(self) -> Optional[Mapping]:
        if self.encrypt_config.exists():
            return yaml.safe_load(self.encrypt_config.read_text())

    def _read_encryption_secret(self) -> Optional[str]:
        config = self._read_encryption_config()
        if not config:
            log.error("Failed to read encryption_config file.")
            return None
        try:
            b64_secret = config["resources"][0]["providers"][0]["aescbc"]["keys"][0]["secret"]
            return base64.b64decode(b64_secret).decode("utf8")
        except (KeyError, IndexError, ValueError):
            log.error("Failed to read and decode encryption_key secret.")
            return None

    def _write_encryption_config(self):
        if not self.encrypt_config.exists():
            log.info("encryption-config doesn't exist on this unit")
            encryption_conf_dir = self.encrypt_config.parent
            encryption_conf_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                self.vaultlocker.create_encrypted_loop_mount(encryption_conf_dir)
            except VaultLockerError:
                # One common cause of this would be deploying on lxd.
                # Should this be more fatal?
                log.exception("Unable to create encrypted mount for storing config.")
                raise

        try:
            secret: str = self.vault_kv.app_kv.get(ENCRYPTION_KEY)
        except VaultNotReadyError:
            log.exception("Failed to retrieve application encryption_key.")
            return

        if secret == self._read_encryption_secret():
            log.info("No change to encryption configuration necessary.")
            return

        log.info("Writing encryption-config for api-server to use")
        secret = base64.b64encode(secret.encode("utf8")).decode("utf8")
        template = Path("templates/encryption-config.yaml").read_text()
        config = yaml.safe_load(template)
        config["resources"][0]["providers"][0]["aescbc"]["keys"][0]["secret"] = secret

        self.encrypt_config.parent.mkdir(parents=True, exist_ok=True)
        self.encrypt_config.write_text(yaml.safe_dump(config))
        self.encrypt_config.chmod(0o600)
