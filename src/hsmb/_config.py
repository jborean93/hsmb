# Copyright: (c) 2024, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import enum

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
from hsmb._provider import (
    CompressionProvider,
    EncryptionProvider,
    HashingProvider,
    SigningProvider,
)


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

    registered_hash_algorithms: list[HashingProvider] | None = None
    registered_ciphers: list[EncryptionProvider] | None = None
    registered_compressor: CompressionProvider | None = None
    registered_signing_algorithms: list[SigningProvider] | None = None

    def __post_init__(self) -> None:
        if self.registered_hash_algorithms is None:
            self.registered_hash_algorithms = [SHA512HashAlgorithm()]

        if self.registered_ciphers is None:
            self.registered_ciphers = [
                AES128GCMCipher(),
                AES128CCMCipher(),
                AES256GCMCipher(),
                AES256CCMCipher(),
            ]

        if self.registered_signing_algorithms is None:
            self.registered_signing_algorithms = [
                AESGMACSigningAlgorithm(),
                AESCMACSigningAlgorithm(),
                HMACSHA256SigningAlgorithm(),
            ]
