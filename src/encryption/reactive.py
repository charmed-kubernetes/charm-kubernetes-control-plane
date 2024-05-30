import json
import logging
import sqlite3
from functools import cached_property
from typing import Any, List, Mapping, Optional

import hvac
import ops

log = logging.getLogger(__name__)


def try_json(s: Optional[str]) -> Optional[Any]:
    """Try to load string as json, return if not possible."""
    try:
        return json.loads(s)
    except (json.decoder.JSONDecodeError, TypeError):
        return s


class UnitKV(ops.Object):
    """Represents a reactive unit.kv storage."""

    def read(self, key: str, default: Optional[Any] = None) -> Optional[Any]:
        """Read from a possible kv table in the .unit-state.db.

        If this is an upgrade from a reactive charm, this kv table will exist.
        If this is a fresh installed, this table won't exist, and this method returns the default
        """
        conn: sqlite3.Connection = self.framework._storage._db
        c = conn.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='kv'")
        result = c.fetchone()[0]
        if result == 1:
            c.execute("SELECT data FROM kv WHERE key=?", [key])
            result = c.fetchone()
        if not result:
            log.info("UnitKV: failed to find key=%s, defaulting to %s", key, default)
            return default
        return try_json(result[0])


# Adapted from charms.reactive
class UnitsView:
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
