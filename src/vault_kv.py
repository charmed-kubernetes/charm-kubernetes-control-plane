import base64
import json
import logging
import socket
from functools import cached_property
from hashlib import md5
from ipaddress import IPv4Address, IPv6Address
from typing import List, Mapping, Optional, Union

import hvac
import ops
import requests

ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter("vault-kv.log: " + logging.BASIC_FORMAT))
log = logging.getLogger(__name__)
log.addHandler(ch)
SECRETS_BACKEND_FORMAT = "charm-{model-uuid}-{app}"


class _UnitsView:
    def __init__(self, relations: List[ops.Relation]) -> None:
        self.relations = relations

    @cached_property
    def received(self) -> Mapping[str, str]:
        combined = {}
        for rel in sorted(self.relations, key=lambda r: r.id, reverse=True):
            for unit in sorted(rel.units, key=lambda u: u.name, reverse=True):
                combined.update(**rel.data[unit])
        return combined


class VaultNotReadyError(Exception):
    """Exception indicating that Vault was accessed before it was ready."""


# Yanked from charmhelpers
# https://github.com/juju/charm-helpers/blob/b78107dc750644b1d868ff4a61748086783e02bd/charmhelpers/contrib/openstack/vaultlocker.py#L155C1-L184C41
def retrieve_secret_id(url, token) -> str:
    """Retrieve a response-wrapped secret_id from Vault

    :param url: URL to Vault Server
    :ptype url: str
    :param token: One shot Token to use
    :ptype token: str
    :returns: secret_id to use for Vault Access
    :rtype: str"""

    client = hvac.Client(url=url, token=token, adapter=hvac.adapters.Request)
    response = client.sys.unwrap()
    if response.status_code == 200:
        data = response.json()
        return data['data']['secret_id']


class _Singleton(type):
    # metaclass to make a class a singleton
    def __call__(cls, *args, **kwargs):
        if not isinstance(getattr(cls, "_singleton_instance", None), cls):
            cls._singleton_instance = super().__call__(*args, **kwargs)
        return cls._singleton_instance


class _VaultBaseKV(dict, metaclass=_Singleton):
    _kwds = {}  # set by subclasses
    _path = None  # set by subclasses
    _vault_kv: "VaultKV" = None # set by subclasses

    def __init__(self):
        response = self._read_path(self._path)
        data = response["data"] if response else {}
        super().__init__(data)

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
            log.info(
                "Logging %s in to {%s}",
                type(self).__name__,
                self._config["vault_url"],
            )
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

    @cached_property
    def _config(self):
        return self._vault_kv.get_vault_config(**self._kwds)

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

    def __init__(self, vault_kv: "VaultKV", *_, **kwds):
        self._kwds = kwds
        self._vault_kv = vault_kv
        unit_num = vault_kv.charm.unit.name.split("/")[1]
        self._path = f"{self._config['secret_backend']}/kv/unit/{unit_num}"
        super().__init__()


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

    Note: This class is a singleton.
    """

    def __init__(self, vault_kv: "VaultKV", *_, **kwds):
        self._kwds = kwds
        self._vault_kv = vault_kv
        # self._kwds attribute must be set first
        # as _config attribute is based off its values
        backend = self._config["secret_backend"]
        unit_num = vault_kv.charm.unit.name.split("/")[1]
        self._path = f"{backend}/kv/app"
        self._hash_path = f"{backend}/kv/app-hashes/{unit_num}"
        super().__init__()
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
        self._new_hashes[key] = md5(serialized).hexdigest()

    def __setitem__(self, key, value):
        """Set value in app data."""
        super().__setitem__(key, value)
        self._rehash(key)
        self._manage_events(key)

    def _manage_events(self, key):
        flag_any_changed = "layer.vault-kv.app-kv.changed"
        flag_key_changed = f"layer.vault-kv.app-kv.changed.{key}"
        flag_key_set = f"layer.vault-kv.app-kv.set.{key}"
        if self.is_changed(key):
            # clear then set flag to ensure triggers are run even if the main
            # flag was never cleared
            self._vault_kv.clear_event(flag_any_changed)
            self._vault_kv.create_event(flag_any_changed)
            self._vault_kv.clear_event(flag_key_changed)
            self._vault_kv.create_event(flag_key_changed)
        if self.get(key) is not None:
            self._vault_kv.create_event(flag_key_set)
        else:
            self._vault_kv.clear_event(flag_key_set)

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


class VaultKVEvent(ops.EventBase):
    """Base class for VaultKV event sources."""

    def __init__(self, handle: ops.Handle, key:str):
        super().__init__(handle)
        self.key = key


class VaultKVCreated(VaultKVEvent):
    """This event is triggered when VaultKV detects a new key in the app kv database in vault."""


class VaultKVCleared(VaultKVEvent):
    """This event is triggered when VaultKV has a key removed from the app kv database in vault."""


class VaultKV(ops.Object):
    """Handles requesting from the key-value vault datastore."""

    _stored = ops.StoredState()
    created = ops.EventSource(VaultKVCreated)
    cleared = ops.EventSource(VaultKVCleared)

    def __init__(self, charm: ops.CharmBase, endpoint: str = "vault-kv"):
        super().__init__(charm, f"layer.{endpoint}")
        self.charm = charm
        self.requires = VaultKVRequires(charm, endpoint)
        self._stored.set_default(token=str(""))
        self._stored.set_default(secret_id=str(""))

    def clear_event(self, key: str):
        """Emit event callback when key is cleared."""
        self.cleared.emit(key)

    def create_event(self, key: str):
        """Emit event callback when key is created."""
        self.created.emit(key)

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
            "secret_id": self._get_secret_id(vault),
        }

    def _get_secret_backend(self, backend_format: str = None, **_):
        variables = {
            "model-uuid": self.model.uuid,
            "app": self.model.app.name,
        }
        fmt = backend_format if backend_format else SECRETS_BACKEND_FORMAT
        return fmt.format(**variables)

    def _get_secret_id(self, vault: "VaultKVRequires"):
        token = vault.unit_token
        if self._stored.token != token:
            log.info("Changed unit_token, getting new secret_id")
            # token is one-shot, but if it changes it might mean that we're
            # being told to rotate the secret ID, or we might not have fetched
            # one yet
            vault_url = vault.vault_url
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

            # update the token in the unitdata.kv now that its been
            # successfully used to retrieve the secret_id
            self._stored.token = token
            self._stored.secret_id = secret_id
        else:
            secret_id = self._stored.secret_id
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
    def endpoint_address(self) -> Optional[Union[IPv4Address, IPv6Address, str]]:
        """Determine the local endpoint network address."""
        binding = self.model.get_binding(self.endpoint)
        if binding:
            return binding.network.bind_address

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
            relation.data[self.unit]["secret_backend"] = name
            relation.data[self.unit]["access_address"] = self.endpoint_address
            relation.data[self.unit]["hostname"] = socket.gethostname()
            relation.data[self.unit]["isolated"] = isolated
            relation.data[self.unit]["unit_name"] = self._unit_name

    @property
    def unit_role_id(self) -> str:
        """Retrieve the AppRole ID for this application unit or None.

        :returns role_id: AppRole ID for unit
        :rtype role_id: str
        """
        for key in [self._unit_name, self.unit.name]:
            role_key = "{}_role_id".format(key)
            value = self._all_joined_units.received.get(role_key)
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
            value = self._all_joined_units.received.get(token_key)
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
                    token = relation.data[unit].get(token_key)
                    if token:
                        tokens.add(token)

        return list(tokens)

    @property
    def vault_url(self):
        """Retrieve the URL to access Vault.

        :returns vault_url: URL to access vault
        :rtype vault_url: str
        """
        return self._all_joined_units.received.get("vault_url")

    @property
    def vault_ca(self):
        """Retrieve the CA published by Vault.

        :returns vault_ca: Vault CA Certificate data
        :rtype vault_ca: str
        """
        encoded_ca = self._all_joined_units.received.get("vault_ca")
        if encoded_ca:
            return base64.b64decode(encoded_ca)
