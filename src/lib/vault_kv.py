import base64
import hashlib
import json
import logging
import socket
from functools import cached_property
from typing import Any, List, Mapping, Optional

import hvac
import ops
import sqlite3
import requests

log = logging.getLogger(__name__)
SECRETS_BACKEND_FORMAT = "charm-{model-uuid}-{app}"


# Adapted from charms.reactive
class _UnitsView:
    """Creates a view of a relation data bags.

    Prioritizes data in lowest relation-id, then unit name
    """

    def __init__(self, relations: List[ops.Relation]) -> None:
        self.relations = relations

    @cached_property
    def received(self) -> Mapping[str, str]:
        combined = {}
        for rel in sorted(self.relations, key=lambda r: r.id, reverse=True):
            for unit in sorted(rel.units, key=lambda u: u.name, reverse=True):
                combined.update(**rel.data[unit])
        return combined


def from_json(s: Optional[str]) -> Optional[Any]:
    try:
        return json.loads(s)
    except (json.decoder.JSONDecodeError, TypeError):
        return s


def _kv_read(conn: sqlite3.Connection, key: str, default: Optional[Any] = None) -> Optional[Any]:
    """Read from a possible kv table in the .unit-state.db.

    If this is an upgrade from a reactive charm, this kv table will exist.
    If this is a fresh installed, this table won't exist, and this method returns the default
    """
    c = conn.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='kv'")
    result = c.fetchone()[0]
    if result == 1:
        c.execute("SELECT data FROM kv WHERE key=?", [key])
        result = c.fetchone()
    if not result:
        return default
    return from_json(result[0])


def _reactive_secret_id(conn: sqlite3.Connection) -> Optional[str]:
    """Read from kv table"""
    return _kv_read(conn, "layer.vault-kv.secret_id")


def _reactive_is_data_changed(
    conn: sqlite3.Connection, data_id: str, data: Any, hash_type: str = "md5"
):
    """Check if the given set of data has changed since the last time
    `data_changed` was called.

    That is, this is a non-destructive way to check if the data has changed.

    :param str data_id: Unique identifier for this set of data.
    :param data: JSON-serializable data.
    :param str hash_type: Any hash algorithm supported by :mod:`hashlib`.
    """
    alg = getattr(hashlib, hash_type)
    serialized = json.dumps(data, sort_keys=True).encode("utf8")
    old_hash = _kv_read(conn, f"reactive.data_changed.{data_id}")
    new_hash = alg(serialized).hexdigest()
    return old_hash != new_hash


# Yanked from charmhelpers
# https://github.com/juju/charm-helpers/blob/b78107dc750644b1d868ff4a61748086783e02bd/charmhelpers/contrib/openstack/vaultlocker.py#L155C1-L184C41
def retrieve_secret_id(url, token) -> str:
    """Retrieve a response-wrapped secret_id from Vault.

    :param url: URL to Vault Server
    :ptype url: str
    :param token: One shot Token to use
    :ptype token: str
    :returns: secret_id to use for Vault Access
    :rtype: str
    """
    client = hvac.Client(url=url, token=token, adapter=hvac.adapters.Request)
    response = client.sys.unwrap()
    if response.status_code == 200:
        data = response.json()
        return data["data"]["secret_id"]


class VaultNotReadyError(Exception):
    """Exception indicating that Vault was accessed before it was ready."""


class _VaultBaseKV(dict):
    def __init__(self, config, path):
        self._config = {}
        self._path = path
        self.update_config(config)
        super().__init__()

    def update_config(self, new_config):
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
            raise VaultNotReadyError() from ex

    @property
    def _client(self):
        """Get an authenticated hvac.Client.

        The authentication token for the client is only valid for 60 seconds,
        after which a new client will need to be authenticated.
        """
        try:
            log.info("Logging %s in to %s", type(self).__name__, self._config["vault_url"])
            client = hvac.Client(url=self._config["vault_url"])
            client.auth.approle.login(self._config["role_id"], secret_id=self._config["secret_id"])
            return client
        except (
            requests.exceptions.ConnectionError,
            hvac.exceptions.VaultDown,
            hvac.exceptions.VaultNotInitialized,
            hvac.exceptions.BadGateway,
            hvac.exceptions.InternalServerError,
        ) as ex:
            raise VaultNotReadyError() from ex

    def __setitem__(self, key, value):
        log.info("Writing data to vault")
        self._client.write(self._path, **{key: value})
        super().__setitem__(key, value)

    def set(self, key, value):
        """Alias in case a KV-like interface is preferred."""
        self[key] = value


class VaultUnitKV(_VaultBaseKV):
    """A simplified interface for storing unit data in Vault.

    The data is scoped to the current unit.

    Keys must be strings, but data can be structured as long as it is
    JSON-serializable.

    This class can be used as a dict, or you can use `self.get` and `self.set`
    for a more KV-like interface. When values are set, via either style, they
    are immediately persisted to Vault. Values are also cached in memory.

    Note: This class is a singleton.
    """

    def __init__(self, config: dict, unit_num: int):
        path = f"{config['secret_backend']}/kv/unit/{unit_num}"
        super().__init__(config, path)


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
        serialized = json.dumps(self[key], sort_keys=True).encode("utf8")
        self._new_hashes[key] = hashlib.md5(serialized).hexdigest()

    def __setitem__(self, key, value):
        """Set value in app data."""
        super().__setitem__(key, value)
        self._rehash(key)
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
        self.requires = VaultKVRequires(charm, endpoint)
        self._stored.set_default(token=None)
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
        for key in self._app_kv.keys():
            # pylint: disable-next=protected-access
            self._app_kv._manage_events(key)

        return self._app_kv

    def _on_commit(self, _: ops.CommitEvent):
        """At hook end, ensure the app hash is consistent in VaultKV."""
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
            self.app_kv.update_config(self.get_vault_config(**self._kwds))
        except VaultNotReadyError:
            return
        self.new_config.emit()

    def _request_vault_access(self, _: ops.RelationJoinedEvent):
        backend_name = self._get_secret_backend()
        # backend can't be isolated or VaultAppKV won't work; see issue #2
        self.requires.request_secret_backend(backend_name, isolated=False)

    def emit_changed_event(self, scope: dict, key: str):
        """Emit event callback when key is created."""
        self.changed.emit(scope, key)

    def get_vault_config(self, **kwds):
        """
        Get the config data needed for this application to access Vault.

        This is only needed if you're using another application, such as
        VaultLocker, using the secrets backend provided by this layer.

        Returns a dictionary containing the following keys:

        * vault_url
        * secret_backend
        * role_id
        * secret_id
        * on_change

        Note: This data is cached in [UnitData][] so anything with access to that
        could access Vault as this application.

        If any of this data changes (such as the secret_id being rotated), this
        layer will set the `layer.vault-kv.config.changed` flag.

        If this is called before the Vault relation is available, it will raise
        `VaultNotReady`.

        [UnitData]: https://charm-helpers.readthedocs.io/en/latest/api/charmhelpers.core.unitdata.html
        """  # noqa
        vault = self.requires
        if not (vault.vault_url and vault.unit_role_id and vault.unit_token):
            raise VaultNotReadyError()
        return {
            "vault_url": vault.vault_url,
            "secret_backend": self._get_secret_backend(**kwds),
            "role_id": vault.unit_role_id,
            "secret_id": self._get_secret_id(),
            "on_change": self.emit_changed_event,
        }

    def _get_secret_backend(self, backend_format: str = None, **_):
        variables = {
            "model-uuid": self.model.uuid,
            "app": self.model.app.name,
        }
        fmt = backend_format if backend_format else SECRETS_BACKEND_FORMAT
        return fmt.format(**variables)

    def _one_shot_token(self) -> Optional[str]:
        """Determine if the current token in the relation-data is an unused one-shot token."""
        rel_token = self.requires.unit_token
        if rel_token is None:
            # relation has yet to set a token, return a new invalid token
            log.info("vault-kv relation has yet to provide a one-shot token")
            return ""
        elif self._stored.token is not None:
            # stored token has been set, compare with the relation token
            if self._stored.token != rel_token:
                # the relation-token is different from the stored-token
                log.info("vault-kv provided a new one-shot token")
                return rel_token
        elif _reactive_is_data_changed(
            self.framework._storage._db, "layer.vault-kv.token", rel_token
        ):
            # If hash is different from when the charm was reactive
            log.info("vault-kv is providing a new one-shot token")
            return rel_token

    def _stored_secret_id(self):
        """Uplift reactive secret-id if the ops version is unset"""
        if self._stored.secret_id is None:
            if old_secret_id := _reactive_secret_id(self.framework._storage._db):
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
                secret_id = retrieve_secret_id(vault_url, token)
            except (
                requests.exceptions.ConnectionError,
                hvac.exceptions.VaultDown,
                hvac.exceptions.VaultNotInitialized,
                hvac.exceptions.BadGateway,
                hvac.exceptions.InternalServerError,
            ) as ex:
                raise VaultNotReadyError() from ex

            # update the token in the StoredData now that its been
            # successfully used to retrieve the secret_id
            self._stored.token = token
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
    def _all_joined_units(self) -> _UnitsView:
        return _UnitsView(self.relations)

    @property
    def _unit_name(self):
        return f"{self.model.uuid}-{self.unit.name}"

    def request_secret_backend(self, name, isolated=True):
        """Request creation and access to a secret backend.

        :param name: name of secret backend to create/access
        :type name: str
        :param isolated: enforce isolation in backend between units
        :type isolated: bool
        """
        for relation in self.relations:
            access_address = ""
            if binding := self.model.get_binding(relation):
                access_address = binding.network.bind_address
            relation.data[self.unit]["secret_backend"] = name
            relation.data[self.unit]["access_address"] = str(access_address)
            relation.data[self.unit]["hostname"] = socket.gethostname()
            relation.data[self.unit]["isolated"] = json.dumps(isolated)
            relation.data[self.unit]["unit_name"] = self._unit_name

    @property
    def unit_role_id(self) -> str:
        """Retrieve the AppRole ID for this application unit or None.

        :returns role_id: AppRole ID for unit
        :rtype role_id: str
        """
        for key in [self._unit_name, self.unit.name]:
            role_key = "{}_role_id".format(key)
            value = from_json(self._all_joined_units.received.get(role_key))
            if value:
                return value

    @property
    def unit_token(self) -> Optional[str]:
        """Retrieve the one-shot token for secret_id retrieval on this unit.

        :returns token: Vault one-shot token for secret_id response
        :rtype token: str
        """
        for key in [self._unit_name, self.unit.name]:
            token_key = "{}_token".format(key)
            value = from_json(self._all_joined_units.received.get(token_key))
            if value:
                return value

    @property
    def all_unit_tokens(self) -> List[str]:
        """Retrieve the one-shot token(s) for secret_id retrieval on this app.

        :returns token: Vault one-shot token for secret_id response
        :rtype token: str
        """
        tokens = set()
        for key in [self._unit_name, self.unit.name]:
            token_key = "{}_token".format(key)
            for relation in self.relations:
                for unit in relation.units:
                    token = from_json(relation.data[unit].get(token_key))
                    if token:
                        tokens.add(token)

        return list(tokens)

    @property
    def vault_url(self):
        """Retrieve the URL to access Vault.

        :returns vault_url: URL to access vault
        :rtype vault_url: str
        """
        return from_json(self._all_joined_units.received.get("vault_url"))

    @property
    def vault_ca(self):
        """Retrieve the CA published by Vault.

        :returns vault_ca: Vault CA Certificate data
        :rtype vault_ca: str
        """
        encoded_ca = from_json(self._all_joined_units.received.get("vault_ca"))
        if encoded_ca:
            return base64.b64decode(encoded_ca)
