# Copyright 2023 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Charm library for the etcd reactive relation.

The module defines an interface for a charm that requires the etcd relation.
It encapsulates the functionality and events related to managing the etcd relation,
including connection, availability of data, and handling of TLS credentials.

It uses events to handle state changes in the etcd relation, such as when a connection is
established (`EtcdConnected`), when etcd data is available (`EtcdAvailable`), and when TLS data
for etcd is available (`EtcdTLSAvailable`).

A class `EtcdReactiveRequires` is defined, which provides an abstraction over the charm's
requires relation to etcd. It encapsulates the functionality to check the status of the
relation, get connection details, and handle client credentials.

This module also provides helper methods for handling client credentials, such as
saving them to local files and retrieving them from the relation data.

You can use this charm library in your charm by adding it as a dependency in your
`charmcraft.yaml` file and then importing the relevant classes and functions.

Example usage:
```python
from charms.kubernetes_libs.v0.etcd import EtcdReactiveRequires

...
    def __init__(self, *args):
        self.etcd = EtcdReactiveRequires(self)
        ...
        # Handle the events from the relation
        self.framework.observe(self.etcd.on.connected, self._on_etcd_connected)
        self.framework.observe(self.etcd.on.available, self._on_etcd_available)
        self.framework.observe(self.etcd.on.tls_available, self._on_etcd_tls_available)

```

"""

import hashlib
import json
import logging
import os
from functools import cached_property
from typing import Optional

from ops.framework import EventBase, EventSource, Object, ObjectEvents, StoredState
from ops.model import Relation

# The unique Charmhub library identifier, never change it
LIBID = "2d422394fe044d61ad1dc044ed051d1b"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

log = logging.getLogger(__name__)


class EtcdAvailable(EventBase):
    """Event emitted when the etcd relation data is available."""

    pass


class EtcdConnected(EventBase):
    """Event emitted when the etcd relation is connected."""

    pass


class EtcdTLSAvailable(EventBase):
    """Event emitted when the etcd relation TLS data is available."""

    pass


class EtcdConsumerEvents(ObjectEvents):
    """Events emitted by the etcd translation interface."""

    available = EventSource(EtcdAvailable)
    connected = EventSource(EtcdConnected)
    tls_available = EventSource(EtcdTLSAvailable)


class EtcdReactiveRequires(Object):
    """Requires side of the etcd interface.

    This class is a translation interface that wraps the requires side
    of the reactive etcd interface.
    """

    state = StoredState()
    on = EtcdConsumerEvents()

    def __init__(self, charm, endpoint="etcd"):
        super().__init__(charm, f"relation-{endpoint}")
        self.charm = charm
        self.endpoint = endpoint

        self.state.set_default(
            connected=False, available=False, tls_available=False, connection_string=""
        )

        for event in (
            charm.on[endpoint].relation_created,
            charm.on[endpoint].relation_joined,
            charm.on[endpoint].relation_changed,
            charm.on[endpoint].relation_departed,
            charm.on[endpoint].relation_broken,
        ):
            self.framework.observe(event, self._check_relation)

    def _check_relation(self, _: EventBase):
        """Check if the relation is available and emit the appropriate event."""
        if self.relation:
            self.state.connected = True
            self.on.connected.emit()
            # etcd is available only if the connection string is available
            if self.get_connection_string():
                self.state.available = True
                self.on.available.emit()
                # etcd tls is available only if the tls data is available
                # (i.e. client cert, client key, ca cert)
                cert = self.get_client_credentials()
                if cert["client_cert"] and cert["client_key"] and cert["client_ca"]:
                    self.state.tls_available = True
                    self.on.tls_available.emit()

    def _get_dict_hash(self, data: dict) -> str:
        """Generate a SHA-256 hash for a dictionary.

        This function converts the dictionary into a JSON string, ensuring it
        is sorted in order. It then generates a SHA-256 hash of this string.

        Args:
            data(dict): The dictionary to be hashed.

        Returns:
            str: The hexadecimal representation of the hash of the dictionary.
        """
        dump = json.dumps(data, sort_keys=True)
        hash_obj = hashlib.sha256()
        hash_obj.update(dump.encode())
        return hash_obj.hexdigest()

    @property
    def is_ready(self):
        """Check if the relation is available and emit the appropriate event."""
        if self.relation:
            if self.get_connection_string():
                cert = self.get_client_credentials()
                if all(cert.get(key) for key in ["client_cert", "client_key", "client_ca"]):
                    return True
        return False

    def get_connection_string(self) -> str:
        """Return the connection string for etcd."""
        remote_data = self._remote_data
        if remote_data:
            return remote_data.get("connection_string")
        return ""

    def get_client_credentials(self) -> dict:
        """Return the client credentials for etcd."""
        remote_data = self._remote_data
        return {
            "client_cert": remote_data.get("client_cert"),
            "client_key": remote_data.get("client_key"),
            "client_ca": remote_data.get("client_ca"),
        }

    @cached_property
    def relation(self) -> Optional[Relation]:
        """Return the relation object for this interface."""
        return self.model.get_relation(self.endpoint)

    @property
    def _remote_data(self):
        """Return the remote relation data for this interface."""
        if not (self.relation and self.relation.units):
            return {}

        first_unit = next(iter(self.relation.units), None)
        data = self.relation.data[first_unit]
        return data

    def save_client_credentials(self, ca_path, cert_path, key_path):
        """Save all the client certificates for etcd to local files."""
        credentials = {"client_key": key_path, "client_cert": cert_path, "client_ca": ca_path}
        for key, path in credentials.items():
            self._save_remote_data(key, path)

    def _save_remote_data(self, key: str, path: str):
        """Save the remote data to a file."""
        value = self._remote_data.get(key)
        if value:
            parent = os.path.dirname(path)
            if not os.path.isdir(parent):
                os.makedirs(parent)
            with open(path, "w") as stream:
                stream.write(value)
