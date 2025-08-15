import base64
import hashlib
import json
import logging
import socket
from functools import cached_property
from typing import List, Optional

import hvac
import ops
import requests

from encryption import reactive

log = logging.getLogger(__name__)
SECRETS_BACKEND_FORMAT = "charm-{model-uuid}-{app}"


class VaultNotReadyError(Exception):
    """Exception indicating that Vault was accessed before it was ready."""

    can_retry: bool = True


class VaultInvalidAccessError(VaultNotReadyError):
    """Exception indicating that Vault cannot be accessed with the current keys."""

    can_retry: bool = False


def _hash_value(value: str) -> str:
    """Hash the value -- a hash can be used in comparison to determine changes."""
    serialized = json.dumps(value, sort_keys=True).encode("utf8")
    return hashlib.md5(serialized).hexdigest()


class _VaultBaseKV(dict):
    def __init__(self, config, path):
        self._config = {}
        self._path = path
        self.update_config(config)
        super().__init__()

    def update_config(self, new_config: dict):
        all_keys = new_config.keys() | self._config.keys()
        if any(new_config.get(key) != self._config.get(key) for key in all_keys):
            self._config = new_config
            response = self._read_path(self._path)
            data = response["data"] if response else {}
            self.update(**data)

    def _read_path(self, path: str):
        """Get an kv path.

        Read from specified path, if the path doesn't exist yet
        it will manifest as this token not being able to access
        that path. Whatever the case, raise VaultNotReadyError()
        """
        try:
            return self._client.read(path)
        except hvac.exceptions.Forbidden as ex:
            raise VaultNotReadyError(f"Failed to read path={path}") from ex

    @property
    def _client(self):
        """Get an authenticated hvac.Client.

        The authentication token for the client is only valid for 60 seconds,
        after which a new client will need to be authenticated.
        """
        url = self._config["vault_url"]
        try:
            log.info("Logging %s into %s", type(self).__name__, url)
            client = hvac.Client(url=url)
            client.auth.approle.login(self._config["role_id"], secret_id=self._config["secret_id"])
            return client
        except (
            requests.exceptions.ConnectionError,
            hvac.exceptions.VaultDown,
            hvac.exceptions.VaultNotInitialized,
            hvac.exceptions.BadGateway,
            hvac.exceptions.InternalServerError,
        ) as ex:
            raise VaultNotReadyError(f"Failed to login to {url}") from ex
        except hvac.exceptions.InvalidRequest as ex:
            raise VaultInvalidAccessError("Invalid role-id or secret-id") from ex

    def __setitem__(self, key, value):
        log.info("Writing key=%s to vault", key)
        self._client.write(self._path, **{key: value})
        super().__setitem__(key, value)


class VaultAppKV(_VaultBaseKV):
    """A simplified interface for storing app data in Vault.

    The data is shared by every unit of the application.

    Keys must be strings, but data can be structured as long as it is
    JSON-serializable.

    This class can be used as a dict, or you can use `self.get` and `self.set`
    for a more KV-like interface. When values are set, via either style, they
    are immediately persisted to Vault. Values are also cached in memory.

    Note: This is intended to be used as a secure replacement for leadership
    data.  Therefore, only the leader should set data here.  This is not
    enforced, but data changed by non-leaders will not trigger hooks on other
    units, so they may not be notified of changes in a timely fashion.
    """

    def __init__(self, config: dict, unit_num: int):
        backend = config["secret_backend"]
        path = f"{backend}/kv/app"
        self._hash_path = f"{backend}/kv/app-hashes/{unit_num}"
        super().__init__(config, path)
        self._load_hashes()

    def _load_hashes(self):
        log.info("Reading hashes from %s", self._hash_path)
        response = self._read_path(self._hash_path)
        self._old_hashes = response["data"] if response else {}
        self._new_hashes = {}
        for key in self.keys():
            self._rehash(key)

    def _rehash(self, key):
        self._new_hashes[key] = _hash_value(self[key])

    def __setitem__(self, key, value):
        """Set value in app data."""
        super().__setitem__(key, value)
        self._rehash(key)
        self._manage_events(key)

    def notify(self):
        """Notifies the current values of all the keys in the dict."""
        for key in self.keys():
            # pylint: disable-next=protected-access
            self._manage_events(key)

    def _manage_events(self, key):
        callback = self._config.get("on_change")
        if self.is_changed(key) and callable(callback):
            callback(dict(**self), key)

    def is_changed(self, key):
        """Determine if the value for the given key has changed.

        In order to detect changes, hashes of the values are also stored
        in Vault.  These hashes are updated automatically at exit via
        `self.update_hashes()`.
        """
        return self._new_hashes.get(key) != self._old_hashes.get(key)

    def any_changed(self):
        """Determine if any data has changed.

        In order to detect changes, hashes of the values are also stored
        in Vault.  These hashes are updated automatically at exit via
        `self.update_hashes()`.
        """
        all_keys = self._new_hashes.keys() | self._old_hashes.keys()
        return any(self.is_changed(key) for key in all_keys)

    def update_hashes(self):
        """Update the hashes in Vault, thus marking all fields as unchanged.

        This is done automatically at exit.
        """
        log.info("Writing hashes to %s", self._hash_path)
        self._client.write(self._hash_path, **self._new_hashes)
        self._old_hashes.clear()
        self._old_hashes.update(self._new_hashes)

    def sum_hashes(self, new=True) -> str:
        """Sum up the hash values."""
        to_sum = self._new_hashes if new else self._old_hashes
        return str(sum(int(digest, base=16) for digest in to_sum.values()))


class VaultKVChanged(ops.EventBase):
    """VaultKV key changed event."""

    def __init__(self, handle: ops.Handle, scope: dict, key: str):
        super().__init__(handle)
        self.scope = scope
        self.key = key


class VaultConfigUpdated(ops.EventBase):
    """Vault Config has updated."""


class VaultKV(ops.Object):
    """Handles requesting from the key-value vault datastore.

    The Charm should have a peer relation in order for leader units
    to notify peers of changes to the VaultAppKV
    """

    _stored = ops.StoredState()
    changed = ops.EventSource(VaultKVChanged)
    new_config = ops.EventSource(VaultConfigUpdated)

    def __init__(
        self, charm: ops.CharmBase, endpoint: str = "vault-kv", peer: str = "peer", **kwds
    ):
        super().__init__(charm, f"layer.{endpoint}")
        self.charm = charm
        self.peer_relation = peer
        self._app_kv = None
        self._kwds = kwds
        self._unit_kv = reactive.UnitKV(charm, f"layer.{endpoint}.unitkv")
        self.requires = VaultKVRequires(charm, endpoint)
        self._stored.set_default(token_hash=None)
        self._stored.set_default(secret_id=None)

        events = charm.on[endpoint]
        self.framework.observe(events.relation_joined, self._request_vault_access)
        self.framework.observe(events.relation_changed, self._update_vault_config)
        self.framework.observe(self.framework.on.commit, self._on_commit)

    @property
    def app_kv(self) -> VaultAppKV:
        if self._app_kv:
            return self._app_kv

        config = self.get_vault_config(**self._kwds)
        self._app_kv = VaultAppKV(config, self.charm.unit.name.split("/")[1])
        self._app_kv.notify()
        return self._app_kv

    def _on_commit(self, e: ops.CommitEvent):
        """At hook end, ensure the app hash is consistent in VaultKV.

        By registering the on.commit event, we robbed this object of
        its natural call to save its own stored state during that event.
        We just need to call the method here to ensure the data is saved.
        """
        self._stored._data.on_commit(e)
        try:
            app_kv = self.app_kv
            if app_kv.any_changed():
                peer_relation = self.charm.model.get_relation(self.peer_relation)
                if self.charm.unit.is_leader() and peer_relation:
                    """force hooks to run on non-leader units"""
                    val = app_kv.sum_hashes()
                    peer_relation.data[self.charm.unit]["vault-kv-nonce"] = val
                # Update the local unit hashes at successful exit
                app_kv.update_hashes()
        except VaultNotReadyError:
            return

    def _update_vault_config(self, _: ops.RelationChangedEvent):
        current_secret_id = self._stored_secret_id()
        try:
            updated_secret_id = self._get_secret_id()
            if current_secret_id == updated_secret_id:
                return
            log.info("Updating vault config")
            self.app_kv.update_config(self.get_vault_config(**self._kwds))
        except VaultNotReadyError:
            return
        self.new_config.emit()

    def _request_vault_access(self, _: ops.RelationJoinedEvent):
        backend_name = self._get_secret_backend()
        self.requires.request_secret_backend(backend_name)

    def get_vault_config(self, **kwds):
        """Get the config data needed for this application to access Vault.

        This is only needed if you're using another application, such as
        VaultLocker, using the secrets backend provided by this library.

        Returns a dictionary containing the following keys:

        * vault_url
        * secret_backend
        * role_id
        * secret_id
        * on_change

        Note: The secret_id is stored in the charm's unit.db along with the
        last used one-shot-token.  When the token changes, a new secret_id is
        fetched from vault.

        If any of this data changes (such as the secret_id being rotated), this
        layer will emit a custom event VaultKVChanged.

        If this is called before the Vault relation is available, it will raise
        `VaultNotReady`.
        """
        vault = self.requires
        if not (vault.vault_url and vault.unit_role_id and vault.unit_token):
            raise VaultNotReadyError("vault-kv relation is missing attributes")
        return {
            "vault_url": vault.vault_url,
            "secret_backend": self._get_secret_backend(**kwds),
            "role_id": vault.unit_role_id,
            "secret_id": self._get_secret_id(),
            "on_change": self.changed.emit,
        }

    def _get_secret_backend(self, backend_format: str = None, **_):
        variables = {
            "model-uuid": self.model.uuid,
            "app": self.model.app.name,
        }
        fmt = backend_format if backend_format else SECRETS_BACKEND_FORMAT
        return fmt.format(**variables)

    def _one_shot_token(self) -> str:
        """Determine if the current token in the relation-data is an unused one-shot token."""
        rel_token = self.requires.unit_token
        if not rel_token:
            # relation has yet to set a token, return a new invalid token
            log.info("vault-kv relation has yet to provide a one-shot token")
            return ""
        if self._stored_token_hash() == _hash_value(rel_token):
            # relation token hash matches the last stored token hash
            log.info("vault-kv relation token hash matches the stored hash")
            return ""
        # the relation-token is different from the stored-token
        log.info("vault-kv is providing a new one-shot token")
        return rel_token

    def _stored_token_hash(self):
        """Uplift reactive token hash if the ops version is unset."""
        if self._stored.token_hash is None:
            if old_token_hash := self._unit_kv.read("reactive.data_changed.layer.vault-kv.token"):
                log.info("vault-kv uplifts token hash from reactive to ops")
                self._stored.token_hash = old_token_hash
        return self._stored.token_hash

    def _stored_secret_id(self):
        """Uplift reactive secret-id if the ops version is unset."""
        if self._stored.secret_id is None:
            if old_secret_id := self._unit_kv.read("layer.vault-kv.secret_id"):
                log.info("vault-kv uplifts secret_id from reactive to ops")
                self._stored.secret_id = old_secret_id
        return self._stored.secret_id

    def _get_secret_id(self):
        if token := self._one_shot_token():
            log.info("Changed unit_token, getting new secret_id")
            # token is one-shot, but if it changes it might mean that we're
            # being told to rotate the secret ID, or we might not have fetched
            # one yet
            vault_url = self.requires.vault_url
            try:
                secret_id = reactive.retrieve_secret_id(vault_url, token)
            except (
                requests.exceptions.ConnectionError,
                hvac.exceptions.VaultDown,
                hvac.exceptions.VaultNotInitialized,
                hvac.exceptions.BadGateway,
                hvac.exceptions.InternalServerError,
            ) as ex:
                raise VaultNotReadyError("Failed to retrieve secret-id at {vault_url}") from ex
            except hvac.exceptions.InvalidRequest as ex:
                raise VaultInvalidAccessError("Invalid one-shot token") from ex

            # update the token in the StoredData now that its been
            # successfully used to retrieve the secret_id
            log.info("Successfully used one_shot_token to collect token")
            self._stored.token_hash = _hash_value(token)
            self._stored.secret_id = secret_id
        else:
            secret_id = self._stored_secret_id()
        return secret_id


class VaultKVRequires(ops.Object):
    """Implements the Requires side of the vault-kv interface."""

    def __init__(self, charm: ops.CharmBase, endpoint: str = "vault-kv"):
        super().__init__(charm, f"relation-{endpoint}")
        self.endpoint = endpoint
        self.unit = self.model.unit

    @cached_property
    def relations(self) -> List[ops.Relation]:
        """List of relations on this endpoint."""
        return self.model.relations[self.endpoint]

    @cached_property
    def _all_joined_units(self) -> reactive.UnitsView:
        return reactive.UnitsView(self.relations)

    @property
    def _unit_name(self) -> str:
        return f"{self.model.uuid}-{self.unit.name}"

    def request_secret_backend(self, name):
        """Request creation and access to a secret backend.

        :param name: name of secret backend to create/access
        :type name: str
        """
        for relation in self.relations:
            access_address = ""
            if binding := self.model.get_binding(relation):
                access_address = binding.network.bind_address
            relation.data[self.unit]["secret_backend"] = name
            relation.data[self.unit]["access_address"] = str(access_address)
            relation.data[self.unit]["hostname"] = socket.gethostname()
            relation.data[self.unit]["isolated"] = json.dumps(False)
            relation.data[self.unit]["unit_name"] = self._unit_name

    @property
    def unit_role_id(self) -> Optional[str]:
        """Retrieve the AppRole ID for this application unit or None.

        :returns role_id: AppRole ID for unit
        """
        for key in [self._unit_name, self.unit.name]:
            role_key = "{}_role_id".format(key)
            if value := reactive.try_json(self._all_joined_units.received.get(role_key)):
                return value
        log.warning("VaultKVRequires: unit role-id not yet available.")

    @property
    def unit_token(self) -> Optional[str]:
        """Retrieve the one-shot token for secret_id retrieval on this unit.

        :returns token: Vault one-shot token for secret_id response
        """
        for key in [self._unit_name, self.unit.name]:
            token_key = "{}_token".format(key)
            if value := reactive.try_json(self._all_joined_units.received.get(token_key)):
                return value
        log.warning("VaultKVRequires: unit token not yet available.")

    @property
    def all_unit_tokens(self) -> List[str]:
        """Retrieve the one-shot token(s) for secret_id retrieval on this app.

        :returns token: Unique list of vault one-shot token for secret_id response
        """
        tokens = set()
        for key in [self._unit_name, self.unit.name]:
            token_key = "{}_token".format(key)
            for relation in self.relations:
                for unit in relation.units:
                    if token := reactive.try_json(relation.data[unit].get(token_key)):
                        tokens.add(token)
        return list(tokens)

    @property
    def vault_url(self) -> Optional[str]:
        """Retrieve the URL to access Vault.

        :returns vault_url: URL to access vault
        """
        return reactive.try_json(self._all_joined_units.received.get("vault_url"))

    @property
    def vault_ca(self) -> Optional[str]:
        """Retrieve the CA published by Vault.

        :returns vault_ca: Vault CA Certificate data
        """
        if encoded_ca := reactive.try_json(self._all_joined_units.received.get("vault_ca")):
            return base64.b64decode(encoded_ca)
