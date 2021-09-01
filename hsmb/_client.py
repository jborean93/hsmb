# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import datetime
import typing
import uuid

import typing_extensions

from hsmb._config import SMBConfig, SMBRole
from hsmb._headers import SMB2Header
from hsmb._messages import Capabilities, Dialect, SecurityModes, SMBMessage
from hsmb._negotiate_contexts import (
    CipherBase,
    CompressionAlgorithmBase,
    HashAlgorithmBase,
    RdmaTransformId,
    SigningAlgorithmBase,
)

if typing.TYPE_CHECKING:
    from hsmb._events import Event

try:
    from typing import Protocol
except ImportError:
    # Python < 3.8
    from typing_extensions import Protocol


class ResponseCallback(Protocol):
    def __call__(
        self,
        __header: SMB2Header,
        __message: SMBMessage,
        __raw: memoryview,
        __state: typing.Dict[str, typing.Any],
    ) -> typing.Optional["Event"]:
        ...


@dataclasses.dataclass
class ClientConfig(SMBConfig):
    """Global SMB client configuration.

    Global data that is required by the client. These fields are defined in
    `MS-SMB2 3.2.1.1 Global`_.

    Attributes:
        connection_table: Active SMB2 connections, indexed by the server name.
        global_file_table: All opened fields, indexed by name.
        client_guid: A global identifier for this client.
        max_dialect: The highest SMB2 dialect that the client implements.
        require_secure_negotiate: Client requires validation of the negotiation
            phase.
        server_list: A dict of server entries, indexed by the server name.
        share_list: A dict of server shares, indexed by the share path.
        compress_all_requests: Empowers the client to compress all requests.

    .. _MS-SMB2 3.2.1.1 Global:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/89f8c694-cbc9-47fb-9996-d7ec35106dc4
    """

    role = SMBRole.CLIENT

    connection_table: typing.Dict[str, "ClientConnection"] = dataclasses.field(default_factory=dict)
    global_file_table: typing.Dict[str, typing.Any] = dataclasses.field(default_factory=dict)
    client_guid: uuid.UUID = dataclasses.field(default_factory=uuid.uuid4)
    max_dialect: Dialect = Dialect.SMB311
    require_secure_negotiate: bool = True
    server_list: typing.Dict[str, "ClientServer"] = dataclasses.field(default_factory=dict)
    share_list: typing.Dict[str, "ClientShare"] = dataclasses.field(default_factory=dict)
    compress_all_requests: bool = False


@dataclasses.dataclass
class ClientConnection:
    session_table: typing.Dict[int, "ClientSession"] = dataclasses.field(default_factory=dict)
    preauth_session_table: typing.Dict[int, "ClientSession"] = dataclasses.field(default_factory=dict)
    outstanding_requests: typing.Dict[int, "ClientPendingRequest"] = dataclasses.field(default_factory=dict)
    sequence_window: typing.List[typing.Tuple[int, int]] = dataclasses.field(default_factory=list)
    gss_negotiate_token: typing.Optional[bytes] = None
    max_transact_size: int = 65536
    max_read_size: int = 65536
    max_write_size: int = 65536
    server_guid: uuid.UUID = uuid.UUID(int=0)
    require_signing: bool = False
    server_name: typing.Optional[str] = None
    # SMB 2.1
    dialect: Dialect = Dialect.UNKNOWN
    supports_file_leasing: bool = False
    supports_multi_credit: bool = False
    client_guid: uuid.UUID = uuid.UUID(int=0)
    # SMB 3.x
    supports_directory_leasing: bool = False
    supports_multi_channel: bool = False
    supports_persistent_handles: bool = False
    supports_encryption: bool = False
    client_capabilities: Capabilities = Capabilities.NONE
    server_capabilities: Capabilities = Capabilities.NONE
    client_security_mode: SecurityModes = SecurityModes.NONE
    server_security_mode: SecurityModes = SecurityModes.NONE
    server: typing.Optional["ClientServer"] = None
    offered_dialects: typing.List[Dialect] = dataclasses.field(default_factory=list)
    # SMB 3.1.1
    preauth_integrity_hash_id: typing.Optional[HashAlgorithmBase] = None
    preauth_integrity_hash_value: bytes = b""
    cipher_id: typing.Optional[CipherBase] = None
    compression_ids: typing.List[CompressionAlgorithmBase] = dataclasses.field(default_factory=list)
    supports_chained_compression: bool = False
    rdma_transform_ids: typing.List[typing.Any] = dataclasses.field(default_factory=list)
    signing_algorithm_id: typing.Optional[SigningAlgorithmBase] = None
    accept_transport_security: bool = True


@dataclasses.dataclass
class ClientSession:
    connection: ClientConnection
    session_id: int
    tree_connect_table: typing.Dict[int, "ClientTreeConnect"] = dataclasses.field(default_factory=dict)
    session_key: bytes = b""
    signing_required: bool = False
    open_table: typing.Dict[int, typing.Any] = dataclasses.field(default_factory=dict)
    is_anonymous: bool = False
    is_guest: bool = False
    channel_list: typing.Dict[int, typing.Any] = dataclasses.field(default_factory=dict)
    channel_sequence: int = 0
    encrypt_data: bool = False
    encryption_key: bytes = b""
    decryption_key: bytes = b""
    signing_key: bytes = b""
    application_key: bytes = b""
    preauth_integrity_hash_value: bytes = b""
    full_session_key: bytes = b""


@dataclasses.dataclass
class ClientTreeConnect:
    share_name: str
    tree_connect_id: int
    session: ClientSession
    is_dfs_share: bool = False
    is_ca_share: bool = False
    encrypt_data: bool = False
    is_scaleout_share: bool = False
    compress_data: bool = False


@dataclasses.dataclass
class ClientOpenFile:
    open_table: typing.Dict = dataclasses.field(default_factory=dict)
    lease_key: bytes = b""
    lease_state: typing.Any = None
    lease_epoch: int = 0


@dataclasses.dataclass
class ClientApplicationOpenFile:
    file_id: int
    tree_connect: ClientTreeConnect
    connection: ClientConnection
    session: ClientSession
    oplock_level: int
    durable: bool
    file_name: str
    resiliant_handle: bool
    last_disconnect_time: int
    resilient_timeout: int
    operation_bucket: typing.List
    desired_access: int
    share_mode: int
    create_options: int
    file_attributes: int
    create_disposition: int
    durable_timeout: int
    outstanding_requests: typing.Dict
    create_guid: uuid.UUID
    is_persistent: bool


@dataclasses.dataclass
class ClientPendingRequest:
    message: SMBMessage
    async_id: int = 0
    cancel_id: uuid.UUID = dataclasses.field(default_factory=uuid.uuid4)
    timestamp: datetime.datetime = dataclasses.field(default_factory=datetime.datetime.now)
    buffer_descriptor_list: typing.List = dataclasses.field(default_factory=list)
    # Custom used by hsmb
    receive_callback: typing.Optional[ResponseCallback] = None
    receive_callback_state: typing.Optional[typing.Dict[str, typing.Any]] = None


@dataclasses.dataclass
class ClientChannel:
    signing_key: bytes
    connection: ClientConnection


@dataclasses.dataclass
class ClientServer:
    """Client Server config.

    Server metadata used by a client connection. These fields are defined in
    `MS-SMB2 3.2.1.9 Per Server`_. The configuration is generated by the client
    connection after receiving the :class:hsmb.NegotiateResponse` message.

    Attributes:
        server_guid: A globally unique identifier (GUID) that is generated by
            the remote server to uniquely identify the remote server.
        dialect_revision: Preferred dialect between client and server.
        capabilities: The capabilities received from the server in the
            :class:`hsmb.NegotiateResponse`.
        security_mode: The security mode received from the server in the
            :class:`hsmb.NegotiateResponse`.
        address_list: A list of IPv4 and IPv6 addresses hosted on the server.
        server_name: The fully qualified domain name, NetBIOS name, or an IP
            address of the server machine.
        cipher_id: The negotiated cipher algorithms between the client and
            server - Dialect 3.1.1 or newer.
        rdma_transform_ids: A list of RDMA transform identifiers, if any,
            negotiated between client and server.
        signing_algorithm_id: An identifier of the signing algorithm, if any,
            negotiated between client and server.

    .. _MS-SMB2 3.2.1.9 Per Server:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/f388d7e0-9bc3-4d9c-98e5-71f8e36b3c4f
    """

    server_guid: uuid.UUID
    dialect_revision: Dialect
    capabilities: Capabilities
    security_mode: SecurityModes
    address_list: typing.List[str]
    server_name: str
    cipher_id: typing.Optional[CipherBase] = None
    # SMB 3.1.1
    rdma_transform_ids: typing.List[RdmaTransformId] = dataclasses.field(default_factory=list)
    signing_algorithm_id: typing.Optional[SigningAlgorithmBase] = None


@dataclasses.dataclass
class ClientShare:
    """Client share config.

    Share metadata used by a client connection. These fields are defined in
    `MS-SMB2 3.2.1.10 Per Share`_. The configuration is generated by the client
    connection after receiving the FIXME type message.

    Attributes:
        path_name: A path that describes the resource that is being shared.
        encrypt_data: Indicates that the server requires messages for accessing
            this share to be encrypted.

    .. _MS-SMB2 3.2.1.10 Per Share:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/9158b3b4-78d3-499d-894d-8ede81091e82
    """

    path_name: str
    encrypt_data: bool
