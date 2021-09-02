# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import abc
import dataclasses
import enum
import struct
import typing
import uuid

from hsmb._exceptions import MalformedPacket
from hsmb._messages import Command, SMB2Header, SMBMessage, TransformHeader


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


class Capabilities(enum.IntFlag):
    NONE = 0x00000000
    DFS = 0x00000001
    LEASING = 0x00000002
    LARGE_MTU = 0x00000004
    MULTI_CHANNEL = 0x00000008
    PERSISTENT_HANDLES = 0x00000010
    DIRECTORY_LEASING = 0x00000020
    ENCRYPTION = 0x00000040


class Cipher(enum.IntEnum):
    NONE = 0x0000
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


class Dialect(enum.IntEnum):
    UNKNOWN = 0x0000
    SMB202 = 0x0202
    SMB210 = 0x0210
    SMB300 = 0x0300
    SMB302 = 0x0302
    SMB311 = 0x0311
    SMB2_WILDCARD = 0x02FF


class TransportCapabilityFlags(enum.IntFlag):
    ACCEPT_TRANSPORT_LEVEL_SECURITY = 0x00000001


class RdmaTransformId(enum.IntEnum):
    NONE = 0x0000
    ENCRYPTION = 0x0001
    SIGNING = 0x0002


class SecurityModes(enum.IntFlag):
    NONE = 0x0000
    SIGNING_ENABLED = 0x0001
    SIGNING_REQUIRED = 0x0002


class SigningAlgorithm(enum.IntEnum):
    HMAC_SHA256 = 0x0000
    AES_CMAC = 0x0001
    AES_GMAC = 0x0002


@dataclasses.dataclass(frozen=True)
class NegotiateContext:
    __slots__ = ("context_type",)

    context_type: ContextType

    def pack(self) -> bytearray:
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

    def pack(self) -> bytearray:
        return bytearray().join(
            [
                len(self.hash_algorithms).to_bytes(2, byteorder="little"),
                len(self.salt).to_bytes(2, byteorder="little"),
                b"".join(h.to_bytes(2, byteorder="little") for h in self.hash_algorithms),
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

    def pack(self) -> bytearray:
        return bytearray().join(
            [
                len(self.ciphers).to_bytes(2, byteorder="little"),
                b"".join(c.to_bytes(2, byteorder="little") for c in self.ciphers),
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

    def pack(self) -> bytearray:
        return bytearray().join(
            [
                len(self.compression_algorithms).to_bytes(2, byteorder="little"),
                b"\x00\x00",  # Padding
                self.flags.to_bytes(4, byteorder="little"),
                b"".join(c.to_bytes(2, byteorder="little") for c in self.compression_algorithms),
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

    def pack(self) -> bytearray:
        return bytearray(self.net_name.encode("utf-16-le"))

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

    def pack(self) -> bytearray:
        return bytearray(self.flags.to_bytes(4, byteorder="little"))

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

    def pack(self) -> bytearray:
        return bytearray().join(
            [
                len(self.rdma_transform_ids).to_bytes(2, byteorder="little"),
                b"\x00\x00",  # Reserved1
                b"\x00\x00\x00\x00",  # Reserved2
                b"".join(r.to_bytes(2, byteorder="little") for r in self.rdma_transform_ids),
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

    def pack(self) -> bytearray:
        return bytearray().join(
            [
                len(self.signing_algorithms).to_bytes(2, byteorder="little"),
                b"".join(a.to_bytes(2, byteorder="little") for a in self.signing_algorithms),
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


class HashAlgorithmBase(metaclass=abc.ABCMeta):
    @classmethod
    @abc.abstractmethod
    def algorithm_id(cls) -> HashAlgorithm:
        ...

    @abc.abstractmethod
    def hash(self, data: bytes) -> bytes:
        ...


class CipherBase(metaclass=abc.ABCMeta):
    @classmethod
    @abc.abstractmethod
    def cipher_id(self) -> Cipher:
        ...

    @abc.abstractmethod
    def encrypt(
        self,
        key: bytes,
        header: "SMB2Header",
        message: bytes,
    ) -> bytes:
        ...

    @abc.abstractmethod
    def decrypt(
        self,
        key: bytes,
        header: "TransformHeader",
        message: bytes,
    ) -> bytes:
        ...


class CompressionAlgorithmBase(metaclass=abc.ABCMeta):
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


class SigningAlgorithmBase(metaclass=abc.ABCMeta):
    @classmethod
    @abc.abstractmethod
    def signing_id(cls) -> SigningAlgorithm:
        ...

    @abc.abstractmethod
    def sign(
        self,
        key: bytes,
        header: "SMB2Header",
        message: bytes,
    ) -> bytes:
        ...


@dataclasses.dataclass(frozen=True)
class SMB1NegotiateRequest(SMBMessage):
    __slots__ = ("dialects",)

    dialects: typing.List[str]

    def __init__(
        self,
        *,
        dialects: typing.List[str],
    ) -> None:
        super().__init__(Command.SMB1_NEGOTIATE)
        object.__setattr__(self, "dialects", dialects)

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        dialects = b"".join([b"\x02" + d.encode() + b"\x00" for d in self.dialects])

        return bytearray().join(
            [
                b"\x00",  # WordCount
                len(dialects).to_bytes(2, byteorder="little"),
                dialects,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["SMB1NegotiateRequest", int]:
        # FIXME
        dialects: typing.List[str] = []

        return SMB1NegotiateRequest(dialects=dialects), 0


@dataclasses.dataclass(frozen=True)
class SMB1NegotiateResponse(SMBMessage):
    __slots__ = ("selected_index",)

    selected_index: int

    def __init__(
        self,
        *,
        selected_index: int,
    ):
        super().__init__(Command.SMB1_NEGOTIATE)
        object.__setattr__(self, "selected_index", selected_index)

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        return bytearray().join(
            [
                b"\x01",  # WordCount
                self.selected_index.to_bytes(2, byteorder="little", signed=True),
                b"\x00\x00",  # ByteCount
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["SMB1NegotiateResponse", int]:
        view = memoryview(data)[offset:]

        selected_index = struct.unpack("<h", view[1:3])[0]
        return SMB1NegotiateResponse(selected_index=selected_index), 0


@dataclasses.dataclass(frozen=True)
class NegotiateRequest(SMBMessage):
    __slots__ = ("dialects", "security_mode", "capabilities", "client_guid", "negotiate_contexts")

    dialects: typing.List[Dialect]
    security_mode: SecurityModes
    capabilities: Capabilities
    client_guid: uuid.UUID
    negotiate_contexts: typing.List[NegotiateContext]

    def __init__(
        self,
        *,
        dialects: typing.List[Dialect],
        security_mode: SecurityModes,
        capabilities: Capabilities,
        client_guid: uuid.UUID,
        negotiate_contexts: typing.Optional[typing.List[NegotiateContext]] = None,
    ) -> None:
        super().__init__(Command.NEGOTIATE)
        object.__setattr__(self, "dialects", dialects)
        object.__setattr__(self, "security_mode", security_mode)
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "client_guid", client_guid)
        object.__setattr__(self, "negotiate_contexts", negotiate_contexts or [])

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        dialects = b"".join(d.to_bytes(2, byteorder="little") for d in self.dialects)
        negotiate_offset = 0
        padding_size = 0
        negotiate_contexts = bytearray()

        if self.negotiate_contexts:
            negotiate_offset = offset_from_header + 36 + len(dialects)
            padding_size = 8 - (negotiate_offset % 8 or 8)
            negotiate_offset += padding_size

            last_idx = len(self.negotiate_contexts) - 1
            for idx, context in enumerate(self.negotiate_contexts):
                context_data = pack_negotiate_context(context)
                negotiate_contexts += context_data

                context_padding_size = 8 - (len(context_data) % 8 or 8)
                if idx != last_idx and context_padding_size:
                    negotiate_contexts += b"\x00" * context_padding_size

        return bytearray().join(
            [
                b"\x24\x00",  # StructureSize(36)
                len(self.dialects).to_bytes(2, byteorder="little"),
                self.security_mode.to_bytes(2, byteorder="little"),
                b"\x00\x00",  # Reserved,
                self.capabilities.to_bytes(4, byteorder="little"),
                self.client_guid.bytes_le,
                negotiate_offset.to_bytes(4, byteorder="little"),
                len(self.negotiate_contexts).to_bytes(2, byteorder="little"),
                b"\x00\x00",  # Reserved2
                dialects,
                (b"\x00" * padding_size),
                negotiate_contexts,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["NegotiateRequest", int]:
        view = memoryview(data)[offset:]

        if len(view) < 36:
            raise MalformedPacket("Negotiate request payload is too small")

        dialect_count = struct.unpack("<H", view[2:4])[0]
        security_mode = SecurityModes(struct.unpack("<H", view[4:6])[0])
        capabilities = Capabilities(struct.unpack("<I", view[8:12])[0])
        client_guid = uuid.UUID(bytes_le=bytes(view[12:28]))
        context_offset = struct.unpack("<I", view[28:32])[0] - offset_from_header
        context_count = struct.unpack("<H", view[32:34])[0]

        end_idx = 36
        if len(view) < (36 + (dialect_count * 2)):
            raise MalformedPacket("Negotiate request payload dialect buffer is out of bounds")

        dialects: typing.List[Dialect] = []
        for _ in range(dialect_count):
            dialects.append(Dialect(struct.unpack("<H", view[end_idx : end_idx + 2])[0]))
            end_idx += 2

        contexts: typing.List[NegotiateContext] = []
        if context_count:
            end_idx = context_offset

            for idx in range(context_count):
                ctx, offset = unpack_negotiate_context(view[end_idx:])
                contexts.append(ctx)

                if idx != context_count - 1:
                    # Adjust for padding
                    offset += 8 - (offset % 8 or 8)

                end_idx += offset

        return (
            NegotiateRequest(
                dialects=dialects,
                security_mode=security_mode,
                capabilities=capabilities,
                client_guid=client_guid,
                negotiate_contexts=contexts,
            ),
            end_idx,
        )


@dataclasses.dataclass(frozen=True)
class NegotiateResponse(SMBMessage):
    __slots__ = (
        "security_mode",
        "dialect_revision",
        "server_guid",
        "capabilities",
        "max_transact_size",
        "max_read_size",
        "max_write_size",
        "system_time",
        "server_start_time",
        "security_buffer",
        "negotiate_contexts",
    )

    security_mode: SecurityModes
    dialect_revision: Dialect
    server_guid: uuid.UUID
    capabilities: Capabilities
    max_transact_size: int
    max_read_size: int
    max_write_size: int
    system_time: int
    server_start_time: int
    security_buffer: typing.Optional[bytes]
    negotiate_contexts: typing.List[NegotiateContext]

    def __init__(
        self,
        *,
        security_mode: SecurityModes,
        dialect_revision: Dialect,
        server_guid: uuid.UUID,
        capabilities: Capabilities,
        max_transact_size: int,
        max_read_size: int,
        max_write_size: int,
        system_time: int = 0,
        server_start_time: int = 0,
        security_buffer: typing.Optional[bytes] = None,
        negotiate_contexts: typing.Optional[typing.List[NegotiateContext]] = None,
    ) -> None:
        super().__init__(Command.NEGOTIATE)
        object.__setattr__(self, "security_mode", security_mode)
        object.__setattr__(self, "dialect_revision", dialect_revision)
        object.__setattr__(self, "server_guid", server_guid)
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "max_transact_size", max_transact_size)
        object.__setattr__(self, "max_read_size", max_read_size)
        object.__setattr__(self, "max_write_size", max_write_size)
        object.__setattr__(self, "system_time", system_time)
        object.__setattr__(self, "server_start_time", server_start_time)
        object.__setattr__(self, "security_buffer", security_buffer)
        object.__setattr__(self, "negotiate_contexts", negotiate_contexts or [])

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        sec_buffer = self.security_buffer or b""
        sec_buffer_offset = offset_from_header + 65
        negotiate_offset = 0
        padding_size = 0
        negotiate_contexts = bytearray()

        if self.negotiate_contexts:
            negotiate_offset = sec_buffer_offset + len(sec_buffer)
            padding_size = 8 - (negotiate_offset % 8 or 8)
            negotiate_offset += padding_size

            last_idx = len(self.negotiate_contexts) - 1
            for idx, context in enumerate(self.negotiate_contexts):
                context_data = pack_negotiate_context(context)
                negotiate_contexts += context_data

                context_padding_size = 8 - (len(context_data) % 8 or 8)
                if idx != last_idx and context_padding_size:
                    negotiate_contexts += b"\x00" * context_padding_size

        return bytearray().join(
            [
                b"\x41\x00",  # StructureSize(65)
                self.security_mode.to_bytes(2, byteorder="little"),
                self.dialect_revision.to_bytes(2, byteorder="little"),
                len(self.negotiate_contexts).to_bytes(2, byteorder="little"),
                self.server_guid.bytes_le,
                self.capabilities.to_bytes(4, byteorder="little"),
                self.max_transact_size.to_bytes(4, byteorder="little"),
                self.max_read_size.to_bytes(4, byteorder="little"),
                self.max_write_size.to_bytes(4, byteorder="little"),
                self.system_time.to_bytes(8, byteorder="little"),
                self.server_start_time.to_bytes(8, byteorder="little"),
                sec_buffer_offset.to_bytes(2, byteorder="little"),
                len(sec_buffer).to_bytes(2, byteorder="little"),
                negotiate_offset.to_bytes(4, byteorder="little"),
                sec_buffer,
                (b"\x00" * padding_size),
                negotiate_contexts,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["NegotiateResponse", int]:
        view = memoryview(data)[offset:]

        if len(view) < 64:
            raise MalformedPacket("Negotiate response payload is too small")

        security_mode = SecurityModes(struct.unpack("<H", view[2:4])[0])
        dialect_revision = Dialect(struct.unpack("<H", view[4:6])[0])
        context_count = struct.unpack("<H", view[6:8])[0]
        server_guid = uuid.UUID(bytes_le=bytes(view[8:24]))
        capabilities = Capabilities(struct.unpack("<I", view[24:28])[0])
        max_transact_size = struct.unpack("<I", view[28:32])[0]
        max_read_size = struct.unpack("<I", view[32:36])[0]
        max_write_size = struct.unpack("<I", view[36:40])[0]
        system_time = struct.unpack("<Q", view[40:48])[0]
        server_start_time = struct.unpack("<Q", view[48:56])[0]
        sec_buffer_offset = struct.unpack("<H", view[56:58])[0] - offset_from_header
        sec_buffer_length = struct.unpack("<H", view[58:60])[0]
        context_offset = struct.unpack("<I", view[60:64])[0] - offset_from_header

        end_idx = 64
        sec_buffer = None
        if sec_buffer_length:
            end_idx = sec_buffer_offset + sec_buffer_length
            if len(view) < end_idx:
                raise MalformedPacket("Negotiate response payload security buffer is out of bounds")
            sec_buffer = bytes(view[sec_buffer_offset:end_idx])

        contexts: typing.List[NegotiateContext] = []
        if context_count:
            end_idx = context_offset

            for idx in range(context_count):
                ctx, offset = unpack_negotiate_context(view[end_idx:])
                contexts.append(ctx)

                if idx != context_count - 1:
                    # Adjust for padding
                    offset += 8 - (offset % 8 or 8)

                end_idx += offset

        return (
            NegotiateResponse(
                security_mode=security_mode,
                dialect_revision=dialect_revision,
                server_guid=server_guid,
                capabilities=capabilities,
                max_transact_size=max_transact_size,
                max_read_size=max_read_size,
                max_write_size=max_write_size,
                system_time=system_time,
                server_start_time=server_start_time,
                security_buffer=sec_buffer,
                negotiate_contexts=contexts,
            ),
            end_idx,
        )


def pack_negotiate_context(
    context: NegotiateContext,
) -> bytearray:
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

    return bytearray().join(
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

    Raises:
        MalformedPacket: The data is too small or the context type specified is
        an unknown type.

    .. _SMB2 NEGOTIATE_CONTEXT Structure:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/15332256-522e-4a53-8cd7-0bd17678a2f7
    """
    view = memoryview(data)

    if len(view) < 8:
        raise MalformedPacket("Negotiate context payload is too small")

    context_type = ContextType(struct.unpack("<H", view[0:2])[0])
    context_length = struct.unpack("<H", view[2:4])[0]

    if len(view) < (8 + context_length):
        raise MalformedPacket("Negotiate context payload is too small")

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
        raise MalformedPacket(f"Unknown negotiate context type {context_type}")

    return context_cls.unpack(context_data), 8 + context_length
