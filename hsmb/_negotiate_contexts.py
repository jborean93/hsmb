# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import enum
import typing


class ContextType(enum.IntEnum):
    PREAUTH_INTEGRITY_CAPABILITIES = 0x0001
    ENCRYPTION_CAPABILITIES = 0x0002
    COMPRESSION_CAPABILITIES = 0x0003
    NETNAME_NEGOTIATE_CONTEXT_ID = 0x0005
    TRANSPORT_CAPABILITIES = 0x0006
    RDMA_TRANSFORM_CAPABILITIES = 0x0007
    SIGNING_CAPABILITIES = 0x0008


class HashAlgorithm(enum.IntEnum):
    SHA512 = 0x0001


class Cipher(enum.IntEnum):
    AES128_CCM = 0x0001
    AES128_GCM = 0x0002
    AES256_CCM = 0x0003
    AES256_GCM = 0x0004


class CompressionCapabilityFlags(enum.IntFlag):
    NONE = 0x00000000
    CHAINED = 0x00000001


class CompressionAlgorithm(enum.IntEnum):
    NONE = 0x0000
    LZNT1 = 0x0001
    LZ77 = 0x0002
    LZ77_HUFFMAN = 0x0003
    PATTERN_V1 = 0x0004


class TransportCapabilityFlags(enum.IntFlag):
    ACCEPT_TRANSPORT_LEVEL_SECURITY = 0x00000001


class RdmaTransformId(enum.IntEnum):
    NONE = 0x0000
    ENCRYPTION = 0x0001
    SIGNING = 0x0002


class SigningAlgorithm(enum.IntEnum):
    HMAC_SHA256 = 0x0000
    AES_CMAC = 0x0001
    AES_GMAC = 0x0002


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
        super().__init__(ContextType.PREAUTH_INTEGRITY_CAPABILITIES)
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
        super().__init__(ContextType.ENCRYPTION_CAPABILITIES)
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
        super().__init__(ContextType.COMPRESSION_CAPABILITIES)
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
        super().__init__(ContextType.NETNAME_NEGOTIATE_CONTEXT_ID)
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
        super().__init__(ContextType.TRANSPORT_CAPABILITIES)
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
        super().__init__(ContextType.RDMA_TRANSFORM_CAPABILITIES)
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
        super().__init__(ContextType.SIGNING_CAPABILITIES)
        object.__setattr__(self, "sigining_algorithms", sigining_algorithms)
