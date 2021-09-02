# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import datetime
import enum
import typing
import uuid

from hsmb._crypto import (
    AES128CCMCipher,
    AES128GCMCipher,
    AES256CCMCipher,
    AES256GCMCipher,
    AESCMACSigningAlgorithm,
    AESGMACSigningAlgorithm,
    HMACSHA256SigningAlgorithm,
    SHA512HashAlgorithm,
)
from hsmb._negotiate import (
    CipherBase,
    CompressionAlgorithmBase,
    Dialect,
    HashAlgorithmBase,
    SigningAlgorithmBase,
)

if typing.TYPE_CHECKING:
    from hsmb._client import ClientConnection, ClientServer, ClientShare


class SMBRole(enum.Enum):
    CLIENT = enum.auto()
    SERVER = enum.auto()


class TransportIdentifier(enum.Enum):
    UNKNOWN = enum.auto()
    DIRECT_TCP = enum.auto()
    NETBIOS_TCP = enum.auto()
    QUIC = enum.auto()


@dataclasses.dataclass
class SMBConfig:
    """Global SMB configuration.

    Global data that is required by both the client and server. This should not
    be created directly, instead use :class:`SMBClientConfig` or
    :class:`SMBServerConfig` for a client and server configuration object
    respectively. These fields are defined in `MS-SMB2 3.1.1.1 Global`_. The
    registered_* fields are set to a known set of values implemented in hsmb
    but can be overriden by specifying a list when creating the config.

    Attributes:
        roles: The role of the caller.
        require_message_signing: Indicates this node requires that messages be
            signed if the the user security context is neight anonymous nor
            guest. If ``False`` signing is not required but may still be done
            if the other node requires it.
        is_encryption_supported: Indicates that encryption is supported by the
            node.
        is_compression_supported: Indicates that compression is supported by
            the node.
        is_chained_compression_supported: Indicates that chained compression is
            supported.
        is_rdma_transform_supported: Indicates that RDMA transform is supported.
        disable_encryption_over_secure_transport: Indicates encryption is
            disabled over a secure transport like QUIC.
        registered_hash_algorithms: A list of :class:`HashAlgorithmBase`
            classes that can be used to hash the pre authentication value. At
            least 1 hash algorithm must be present in the config to negotiate
            SMB 3.1.1.
        registered_ciphers: A list of :class:`CipherBase`, in priority order,
            to negotiate for the encryption capabilities with the peer.
        registered_compressor: A list of :class:`CompressorBase`, in priority
            order, to negotiate for the compression capabilities with the peer.
        registered_signing_algorithms: A list of :class:`SignerBase`, in
            priority order, to negotiate for the signing capabilities with the
            peer.

    .. _MS-SMB2 3.1.1.1 Global:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/95a74d96-93a7-42ea-af1a-688c17c522ee
    """

    role: SMBRole = dataclasses.field(init=False)

    require_message_signing: bool = True
    is_encryption_supported: bool = True
    is_compression_supported: bool = True
    is_chained_compression_supported: bool = True
    is_rdma_transform_supported: bool = True
    disable_encryption_over_secure_transport: bool = True

    registered_hash_algorithms: typing.Optional[typing.List[typing.Type[HashAlgorithmBase]]] = None
    registered_ciphers: typing.Optional[typing.List[typing.Type[CipherBase]]] = None
    registered_compressors: typing.Optional[typing.List[typing.Type[CompressionAlgorithmBase]]] = None
    registered_signing_algorithms: typing.Optional[typing.List[typing.Type[SigningAlgorithmBase]]] = None

    def __post_init__(self) -> None:
        if self.registered_hash_algorithms is None:
            self.registered_hash_algorithms = [SHA512HashAlgorithm]

        if self.registered_ciphers is None:
            self.registered_ciphers = [AES128GCMCipher, AES128CCMCipher, AES256GCMCipher, AES256CCMCipher]

        if self.registered_compressors is None:
            self.registered_compressors = []

        if self.registered_signing_algorithms is None:
            self.registered_signing_algorithms = [
                AESGMACSigningAlgorithm,
                AESCMACSigningAlgorithm,
                HMACSHA256SigningAlgorithm,
            ]


@dataclasses.dataclass
class SMBClientConfig(SMBConfig):
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
class SMBServerConfig(SMBConfig):
    """Global SMB server configuration.

    Global data that is required by the server. These fields are defined in
    `MS-SMB2 3.3.1.5 Global`_.

    Attributes:

    .. _MS-SMB2 3.3.1.5 Global:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/b3803e3b-e849-4827-a558-b2403deb24d9
    """

    role = SMBRole.SERVER

    # server_statistics
    # server_enabled
    share_list: typing.List = dataclasses.field(default_factory=list)
    global_open_table: typing.Dict[str, typing.Any] = dataclasses.field(default_factory=dict)
    global_session_table: typing.Dict[int, typing.Any] = dataclasses.field(default_factory=dict)
    connection_list: typing.Dict[str, typing.Any] = dataclasses.field(default_factory=dict)
    server_guid: uuid.UUID = dataclasses.field(default_factory=uuid.uuid4)
    server_start_time: datetime.datetime = dataclasses.field(default_factory=datetime.datetime.now)
    is_dfs_capable: bool = False
    # server_side_copy_max_number_of_chunks: int = 0
    # server_side_copy_max_data_size: int = 0
    # server_hash_level: ServerHashLevel = something
    global_lease_table_list: typing.Dict[str, typing.Any] = dataclasses.field(default_factory=dict)
    # max_resiliency_timeout: int = 0
    # resilient_open_scavenger_expiry_time: int = 0
    global_client_table: typing.Dict[uuid.UUID, typing.Any] = dataclasses.field(default_factory=dict)
    encrypt_data: bool = False
    reject_unencrypted_access: bool = False
    is_multi_channel_capable: bool = False
    allow_anonymous_access: bool = False
    is_shared_vhd_supported: bool = False
    max_cluster_dialect: Dialect = Dialect.SMB311
    supports_tree_connect_extn: bool = False
    allow_named_pipe_access_over_quic: bool = False
