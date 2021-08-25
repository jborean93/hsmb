# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import abc
import dataclasses
import enum
import hashlib
import struct
import typing

try:
    import cryptography
except ImportError:
    cryptography = False

try:
    import xca
except ImportError:
    xca = None


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

    def pack(self) -> bytes:
        raise NotImplementedError()

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset: int = 0,
    ) -> "NegotiateContext":
        raise NotImplementedError()


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

    def pack(self) -> bytes:
        return b"".join(
            [
                len(self.hash_algorithms).to_bytes(2, byteorder="little"),
                len(self.salt).to_bytes(2, byteorder="little"),
                b"".join(h.value.to_bytes(2, byteorder="little") for h in self.hash_algorithms),
                self.salt,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset: int = 0,
    ) -> "PreauthIntegrityCapabilities":
        view = memoryview(data)[offset:]

        algorithm_count = struct.unpack("<H", view[0:2])[0]
        algorithm_length = algorithm_count * 2
        salt_length = struct.unpack("<H", view[2:4])[0]

        algorithms = []
        for i in range(algorithm_count):
            offset = i * 2
            val = struct.unpack("<H", view[4 + offset : 6 + offset])[0]
            algorithms.append(HashAlgorithm(val))

        salt = bytes(view[4 + algorithm_length : 4 + algorithm_length + salt_length])

        return PreauthIntegrityCapabilities(
            hash_algorithms=algorithms,
            salt=salt,
        )


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

    def pack(self) -> bytes:
        return b"".join(
            [
                len(self.ciphers).to_bytes(2, byteorder="little"),
                b"".join(c.value.to_bytes(2, byteorder="little") for c in self.ciphers),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset: int = 0,
    ) -> "EncryptionCapabilities":
        view = memoryview(data)[offset:]

        cipher_count = struct.unpack("<H", view[0:2])[0]

        ciphers = []
        for i in range(cipher_count):
            offset = i * 2
            val = struct.unpack("<H", view[2 + offset : 4 + offset])[0]
            ciphers.append(Cipher(val))

        return EncryptionCapabilities(ciphers=ciphers)


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

    def pack(self) -> bytes:
        return b"".join(
            [
                len(self.compression_algorithms).to_bytes(2, byteorder="little"),
                b"\x00\x00",  # Padding
                self.flags.value.to_bytes(4, byteorder="little"),
                b"".join(c.value.to_bytes(2, byteorder="little") for c in self.compression_algorithms),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset: int = 0,
    ) -> "CompressionCapabilities":
        view = memoryview(data)[offset:]

        algo_count = struct.unpack("<H", view[0:2])[0]
        flags = CompressionCapabilityFlags(struct.unpack("<I", view[4:8])[0])

        algos = []
        for i in range(algo_count):
            offset = i * 2
            val = struct.unpack("<H", view[8 + offset : 10 + offset])[0]
            algos.append(CompressionAlgorithm(val))

        return CompressionCapabilities(flags=flags, compression_algorithms=algos)


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

    def pack(self) -> bytes:
        return self.net_name.encode("utf-16-le")

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset: int = 0,
    ) -> "NetnameNegotiate":
        view = memoryview(data)[offset:]

        return NetnameNegotiate(net_name=bytes(view).decode("utf-16-le"))


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

    def pack(self) -> bytes:
        return self.flags.value.to_bytes(4, byteorder="little")

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset: int = 0,
    ) -> "TransportCapabilities":
        view = memoryview(data)[offset:]

        flags = TransportCapabilityFlags(struct.unpack("<I", view[0:4])[0])
        return TransportCapabilities(flags=flags)


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

    def pack(self) -> bytes:
        return b"".join(
            [
                len(self.rdma_transform_ids).to_bytes(2, byteorder="little"),
                b"\x00\x00",  # Reserved1
                b"\x00\x00\x00\x00",  # Reserved2
                b"".join(r.value.to_bytes(2, byteorder="little") for r in self.rdma_transform_ids),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset: int = 0,
    ) -> "RdmaTransformCapabilities":
        view = memoryview(data)[offset:]

        transform_count = struct.unpack("<H", view[0:2])[0]

        ids = []
        for i in range(transform_count):
            offset = i * 2
            val = struct.unpack("<H", view[8 + offset : 10 + offset])[0]
            ids.append(RdmaTransformId(val))

        return RdmaTransformCapabilities(rdma_transform_ids=ids)


@dataclasses.dataclass(frozen=True)
class SigningCapabilities(NegotiateContext):
    __slots__ = ("signing_algorithms",)

    signing_algorithms: typing.List[SigningAlgorithm]

    def __init__(
        self,
        *,
        signing_algorithms: typing.List[SigningAlgorithm],
    ) -> None:
        super().__init__(ContextType.SIGNING_CAPABILITIES)
        object.__setattr__(self, "signing_algorithms", signing_algorithms)

    def pack(self) -> bytes:
        return b"".join(
            [
                len(self.signing_algorithms).to_bytes(2, byteorder="little"),
                b"".join(a.value.to_bytes(2, byteorder="little") for a in self.signing_algorithms),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset: int = 0,
    ) -> "SigningCapabilities":
        view = memoryview(data)[offset:]

        algo_count = struct.unpack("<H", view[0:2])[0]

        algos = []
        for i in range(algo_count):
            offset = i * 2
            val = struct.unpack("<H", view[2 + offset : 4 + offset])[0]
            algos.append(SigningAlgorithm(val))

        return SigningCapabilities(signing_algorithms=algos)


def pack_negotiate_context(
    context: NegotiateContext,
) -> bytes:
    """Pack the Negotiate Context object.

    Packs the Negotiate Context object into bytes. The value is packed
    according to the structure defined at `SMB2 NEGOTIATE_CONTEXT Structure`_.

    Args:
        context: The context to pack.

    Returns:
        bytes: The packed context.

    .. _SMB2 NEGOTIATE_CONTEXT Structure:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/15332256-522e-4a53-8cd7-0bd17678a2f7
    """
    context_data = context.pack()

    return b"".join(
        [
            context.context_type.to_bytes(2, byteorder="little"),
            len(context_data).to_bytes(2, byteorder="little"),
            b"\x00\x00\x00\x00",  # Reserved
            context_data,
        ]
    )


def unpack_negotiate_context(
    data: typing.Union[bytes, bytearray, memoryview],
) -> typing.Tuple[NegotiateContext, int]:
    """Unpack the Negotiate Context bytes.

    Unpacks the Negotiate Context bytes value to the object it represents. The
    value is unpacked according to the structure defined at
    `SMB2 NEGOTIATE_CONTEXT Structure`_.

    Args:
        data: The data to unpack.

    Returns:
        Tuple[NegotiateContext, int]: The unpacked context and the length of
        context (including padding to the 8 byte boundary) that was unpacked.

    .. _SMB2 NEGOTIATE_CONTEXT Structure:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/15332256-522e-4a53-8cd7-0bd17678a2f7
    """
    view = memoryview(data)

    context_type = ContextType(struct.unpack("<H", view[0:2])[0])
    context_length = struct.unpack("<H", view[2:4])[0]
    context_data = view[8 : 8 + context_length]

    context_cls: typing.Optional[typing.Type[NegotiateContext]] = {
        ContextType.PREAUTH_INTEGRITY_CAPABILITIES: PreauthIntegrityCapabilities,
        ContextType.ENCRYPTION_CAPABILITIES: EncryptionCapabilities,
        ContextType.COMPRESSION_CAPABILITIES: CompressionCapabilities,
        ContextType.NETNAME_NEGOTIATE_CONTEXT_ID: NetnameNegotiate,
        ContextType.TRANSPORT_CAPABILITIES: TransportCapabilities,
        ContextType.RDMA_TRANSFORM_CAPABILITIES: RdmaTransformCapabilities,
        ContextType.SIGNING_CAPABILITIES: SigningCapabilities,
    }.get(context_type, None)
    if not context_cls:
        raise ValueError(f"Unknown negotiate context type {context_type}")

    return context_cls.unpack(context_data), 8 + context_length


class HashAlgorithmBase(metaclass=abc.ABCMeta):
    @classmethod
    @abc.abstractmethod
    def algorithm_id(cls) -> HashAlgorithm:
        ...

    @abc.abstractmethod
    def hash(self, data: bytes) -> bytes:
        ...


class SHA512HashAlgorithm(HashAlgorithmBase):
    @classmethod
    def algorithm_id(cls) -> HashAlgorithm:
        return HashAlgorithm.SHA512

    def hash(self, data: bytes) -> bytes:
        return hashlib.sha512(data).digest()


DEFAULT_HASHERS: typing.List[typing.Type[HashAlgorithmBase]] = [SHA512HashAlgorithm]


class CipherBase(metaclass=abc.ABCMeta):
    @classmethod
    @abc.abstractmethod
    def cipher_id(self) -> Cipher:
        ...

    @abc.abstractmethod
    def encrypt(self) -> bytes:
        ...

    @abc.abstractmethod
    def decrypt(self) -> bytes:
        ...


DEFAULT_CIPHERS: typing.List[typing.Type[CipherBase]] = []
if cryptography:

    class AES128CCMCipher(CipherBase):
        @classmethod
        def cipher_id(cls) -> Cipher:
            return Cipher.AES128_CCM

        def encrypt(self) -> bytes:
            return b""

        def decrypt(self) -> bytes:
            return b""

    DEFAULT_CIPHERS = [AES128CCMCipher]


class CompressorBase(metaclass=abc.ABCMeta):
    @classmethod
    @abc.abstractmethod
    def compression_id(cls) -> CompressionAlgorithm:
        ...

    @abc.abstractmethod
    def compress(self) -> bytes:
        ...

    @abc.abstractmethod
    def decompress(self) -> bytes:
        ...


DEFAULT_COMPRESSORS: typing.List[typing.Type[CompressorBase]] = []
if xca:

    class LZ77HuffmanCompressor(CompressorBase):
        @classmethod
        def compression_id(cls) -> CompressionAlgorithm:
            return CompressionAlgorithm.LZ77_HUFFMAN

        def compress(self) -> bytes:
            ...

        def decompress(self) -> bytes:
            ...

    DEFAULT_COMPRESSORS = [LZ77HuffmanCompressor]


class SignerBase(metaclass=abc.ABCMeta):
    @classmethod
    @abc.abstractmethod
    def signing_id(cls) -> SigningAlgorithm:
        ...

    @abc.abstractmethod
    def sign(self) -> bytes:
        ...


DEFAULT_SIGNERS: typing.List[typing.Type[SignerBase]] = []
