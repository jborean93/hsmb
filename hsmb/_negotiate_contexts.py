# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import enum
import typing


class ContextType(enum.IntEnum):
    preauth_integrity_capabilities = 0x0001
    encryption_capabilities = 0x0002
    compression_capabilities = 0x0003
    netname_negotiate_context_id = 0x0005
    transport_capabilities = 0x0006
    rdma_transform_capabilities = 0x0007
    signing_capabilities = 0x0008


class HashAlgorithm(enum.IntEnum):
    sha512 = 0x0001


class Cipher(enum.IntEnum):
    aes128_ccm = 0x0001
    aes128_gcm = 0x0002
    aes256_ccm = 0x0003
    aes256_gcm = 0x0004


class CompressionCapabilityFlags(enum.IntFlag):
    none = 0x00000000
    chained = 0x00000001


class CompressionAlgorithm(enum.IntEnum):
    none = 0x0000
    lznt1 = 0x0001
    lz77 = 0x0002
    lz77_huffman = 0x0003
    pattern_v1 = 0x0004


class TransportCapabilityFlags(enum.IntFlag):
    accept_transport_level_security = 0x00000001


class RdmaTransformId(enum.IntEnum):
    none = 0x0000
    encryption = 0x0001
    signing = 0x0002


class SigningAlgorithm(enum.IntEnum):
    hmac_sha256 = 0x0000
    aes_cmac = 0x0001
    aes_gmac = 0x0002


@dataclasses.dataclass(frozen=True)
class NegotiateContext:
    __slots__ = ("context_type",)

    context_type: ContextType


@dataclasses.dataclass(frozen=True)
class PreauthIntegrityCapabilities(NegotiateContext):
    __slots__ = ("hash_algorithms", "salt")

    hash_algorithms: typing.List[HashAlgorithm]
    salt: bytes

    def __init__(
        self,
        *,
        hash_algorithms: typing.List[HashAlgorithm],
        salt: bytes,
    ) -> None:
        super().__init__(ContextType.preauth_integrity_capabilities)
        object.__setattr__(self, "hash_algorithms", hash_algorithms)
        object.__setattr__(self, "salt", salt)


@dataclasses.dataclass(frozen=True)
class EncryptionCapabilities(NegotiateContext):
    __slots__ = ("ciphers",)

    ciphers: typing.List

    def __init__(
        self,
        *,
        ciphers: typing.List[Cipher],
    ) -> None:
        super().__init__(ContextType.encryption_capabilities)
        object.__setattr__(self, "ciphers", ciphers)


@dataclasses.dataclass(frozen=True)
class CompressionCapabilities(NegotiateContext):
    __slots__ = ("flags", "compression_algorithms")

    flags: CompressionCapabilityFlags
    compression_algorithms: typing.List[CompressionAlgorithm]

    def __init__(
        self,
        *,
        flags: CompressionCapabilityFlags,
        compression_algorithms: typing.List[CompressionAlgorithm],
    ) -> None:
        super().__init__(ContextType.compression_capabilities)
        object.__setattr__(self, "flags", flags)
        object.__setattr__(self, "compression_algorithms", compression_algorithms)


@dataclasses.dataclass(frozen=True)
class NetnameNegotiate(NegotiateContext):
    __slots__ = ("net_name",)

    net_name: str

    def __init__(
        self,
        *,
        net_name: str,
    ) -> None:
        super().__init__(ContextType.netname_negotiate_context_id)
        object.__setattr__(self, "net_name", net_name)


@dataclasses.dataclass(frozen=True)
class TransportCapabilities(NegotiateContext):
    __slots__ = ("flags",)

    flags: TransportCapabilityFlags

    def __init__(
        self,
        *,
        flags: TransportCapabilityFlags,
    ) -> None:
        super().__init__(ContextType.transport_capabilities)
        object.__setattr__(self, "flags", flags)


@dataclasses.dataclass(frozen=True)
class RdmaTransformCapabilities(NegotiateContext):
    __slots__ = ("rdma_transform_ids",)

    rdma_transform_ids: typing.List[RdmaTransformId]

    def __init__(
        self,
        *,
        rdma_transform_ids: typing.List[RdmaTransformId],
    ) -> None:
        super().__init__(ContextType.rdma_transform_capabilities)
        object.__setattr__(self, "rdma_transform_ids", rdma_transform_ids)


@dataclasses.dataclass(frozen=True)
class SigningCapabilities(NegotiateContext):
    __slots__ = ("signing_algorithms",)

    signing_algorithms: typing.List[SigningAlgorithm]

    def __init__(
        self,
        *,
        sigining_algorithms: typing.List[SigningAlgorithm],
    ) -> None:
        super().__init__(ContextType.signing_capabilities)
        object.__setattr__(self, "sigining_algorithms", sigining_algorithms)
