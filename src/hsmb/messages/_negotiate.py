# Copyright: (c) 2024, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import enum
import struct
import uuid

from hsmb._enum_extras import OptionalIntEnum
from hsmb._exceptions import MalformedPacket
from hsmb.messages._messages import Command, SMBMessage


class NegotiateContextType(OptionalIntEnum):
    PREAUTH_INTEGRITY_CAPABILITIES = 0x0001
    ENCRYPTION_CAPABILITIES = 0x0002
    COMPRESSION_CAPABILITIES = 0x0003
    NETNAME_NEGOTIATE_CONTEXT_ID = 0x0005
    TRANSPORT_CAPABILITIES = 0x0006
    RDMA_TRANSFORM_CAPABILITIES = 0x0007
    SIGNING_CAPABILITIES = 0x0008


class HashAlgorithm(OptionalIntEnum):
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


class Cipher(OptionalIntEnum):
    NONE = 0x0000
    AES128_CCM = 0x0001
    AES128_GCM = 0x0002
    AES256_CCM = 0x0003
    AES256_GCM = 0x0004


class CompressionCapabilityFlags(enum.IntFlag):
    NONE = 0x00000000
    CHAINED = 0x00000001


class CompressionAlgorithm(OptionalIntEnum):
    NONE = 0x0000
    LZNT1 = 0x0001
    LZ77 = 0x0002
    LZ77_HUFFMAN = 0x0003
    PATTERN_V1 = 0x0004


class Dialect(OptionalIntEnum):
    UNKNOWN = 0x0000
    SMB202 = 0x0202
    SMB210 = 0x0210
    SMB300 = 0x0300
    SMB302 = 0x0302
    SMB311 = 0x0311
    SMB2_WILDCARD = 0x02FF


class TransportCapabilityFlags(enum.IntFlag):
    NONE = 0x00000000
    ACCEPT_TRANSPORT_LEVEL_SECURITY = 0x00000001


class RdmaTransformId(OptionalIntEnum):
    NONE = 0x0000
    ENCRYPTION = 0x0001
    SIGNING = 0x0002


class SecurityModes(enum.IntFlag):
    NONE = 0x0000
    SIGNING_ENABLED = 0x0001
    SIGNING_REQUIRED = 0x0002


class SigningAlgorithm(OptionalIntEnum):
    HMAC_SHA256 = 0x0000
    AES_CMAC = 0x0001
    AES_GMAC = 0x0002


def _unpack_negotiate_context(
    name: str,
    context_type: NegotiateContextType | None,
    view: memoryview,
) -> tuple[NegotiateContextType, int, memoryview]:
    """Unpacks the raw Negotiate Context structure."""
    if len(view) < 4:
        raise MalformedPacket(f"Not enough data to unpack {name!s}")

    actual_context_type = NegotiateContextType(struct.unpack("<H", view[0:2])[0])
    if context_type and actual_context_type != context_type:
        raise MalformedPacket(
            f"Data is for {actual_context_type!s}, expecting {context_type!s}"
        )

    context_length = struct.unpack("<H", view[2:4])[0] + 8

    if len(view) < context_length:
        raise MalformedPacket(f"Not enough data to unpack {name!s}")

    return actual_context_type, context_length, view[8:context_length]


@dataclasses.dataclass(frozen=True)
class NegotiateContext:
    __slots__ = "context_type"

    context_type: NegotiateContextType

    @property
    def data(self) -> bytes:
        raise NotImplementedError()

    def pack(self) -> bytearray:
        context_data = self.data

        return bytearray().join(
            [
                self.context_type.to_bytes(2, byteorder="little"),
                len(context_data).to_bytes(2, byteorder="little"),
                b"\x00\x00\x00\x00",  # Reserved
                context_data,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: bytes | bytearray | memoryview,
        offset: int = 0,
    ) -> tuple[NegotiateContext, int]:
        view = memoryview(data)[offset:]

        # Just check/get the first 2 bytes for the context type. The subsequent class unpack method checks the rest.
        if len(view) < 2:
            raise MalformedPacket("Negotiate context payload is too small")
        context_type = NegotiateContextType(struct.unpack("<H", view[0:2])[0])

        context_cls: type[NegotiateContext] = {
            NegotiateContextType.PREAUTH_INTEGRITY_CAPABILITIES: PreauthIntegrityCapabilities,
            NegotiateContextType.ENCRYPTION_CAPABILITIES: EncryptionCapabilities,
            NegotiateContextType.COMPRESSION_CAPABILITIES: CompressionCapabilities,
            NegotiateContextType.NETNAME_NEGOTIATE_CONTEXT_ID: NetnameNegotiate,
            NegotiateContextType.TRANSPORT_CAPABILITIES: TransportCapabilities,
            NegotiateContextType.RDMA_TRANSFORM_CAPABILITIES: RdmaTransformCapabilities,
            NegotiateContextType.SIGNING_CAPABILITIES: SigningCapabilities,
        }.get(context_type, UnknownNegotiateContext)

        return context_cls.unpack(view)


@dataclasses.dataclass(frozen=True)
class UnknownNegotiateContext(NegotiateContext):
    __slots__ = ("_data",)

    _data: bytes

    def __init__(
        self,
        *,
        context_type: NegotiateContextType,
        data: bytes,
    ) -> None:
        super().__init__(context_type)
        object.__setattr__(self, "_data", data)

    @property
    def data(self) -> bytes:
        return self.data

    @classmethod
    def unpack(
        cls,
        data: bytes | bytearray | memoryview,
        offset: int = 0,
    ) -> tuple[UnknownNegotiateContext, int]:
        context_type, length, view = _unpack_negotiate_context(
            cls.__name__, None, memoryview(data)[offset:]
        )
        return (
            UnknownNegotiateContext(context_type=context_type, data=bytes(view)),
            length,
        )


@dataclasses.dataclass(frozen=True)
class PreauthIntegrityCapabilities(NegotiateContext):
    __slots__ = ("hash_algorithms", "salt")

    hash_algorithms: list[HashAlgorithm]
    salt: bytes

    def __init__(
        self,
        *,
        hash_algorithms: list[HashAlgorithm],
        salt: bytes,
    ) -> None:
        super().__init__(NegotiateContextType.PREAUTH_INTEGRITY_CAPABILITIES)
        object.__setattr__(self, "hash_algorithms", hash_algorithms)
        object.__setattr__(self, "salt", salt)

    @property
    def data(self) -> bytes:
        return b"".join(
            [
                len(self.hash_algorithms).to_bytes(2, byteorder="little"),
                len(self.salt).to_bytes(2, byteorder="little"),
                b"".join(
                    h.to_bytes(2, byteorder="little") for h in self.hash_algorithms
                ),
                self.salt,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: bytes | bytearray | memoryview,
        offset: int = 0,
    ) -> tuple[PreauthIntegrityCapabilities, int]:
        _, length, view = _unpack_negotiate_context(
            cls.__name__,
            NegotiateContextType.PREAUTH_INTEGRITY_CAPABILITIES,
            memoryview(data)[offset:],
        )

        algorithm_count = struct.unpack("<H", view[0:2])[0]
        algorithm_length = algorithm_count * 2
        salt_length = struct.unpack("<H", view[2:4])[0]

        algorithms = []
        for i in range(algorithm_count):
            offset = i * 2
            val = struct.unpack("<H", view[4 + offset : 6 + offset])[0]
            algorithms.append(HashAlgorithm(val))

        salt = bytes(view[4 + algorithm_length : 4 + algorithm_length + salt_length])

        return (
            PreauthIntegrityCapabilities(
                hash_algorithms=algorithms,
                salt=salt,
            ),
            length,
        )


@dataclasses.dataclass(frozen=True)
class EncryptionCapabilities(NegotiateContext):
    __slots__ = ("ciphers",)

    ciphers: list

    def __init__(
        self,
        *,
        ciphers: list[Cipher],
    ) -> None:
        super().__init__(NegotiateContextType.ENCRYPTION_CAPABILITIES)
        object.__setattr__(self, "ciphers", ciphers)

    @property
    def data(self) -> bytes:
        return b"".join(
            [
                len(self.ciphers).to_bytes(2, byteorder="little"),
                b"".join(c.to_bytes(2, byteorder="little") for c in self.ciphers),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: bytes | bytearray | memoryview,
        offset: int = 0,
    ) -> tuple[EncryptionCapabilities, int]:
        _, length, view = _unpack_negotiate_context(
            cls.__name__,
            NegotiateContextType.ENCRYPTION_CAPABILITIES,
            memoryview(data)[offset:],
        )

        cipher_count = struct.unpack("<H", view[0:2])[0]

        ciphers = []
        for i in range(cipher_count):
            offset = i * 2
            val = struct.unpack("<H", view[2 + offset : 4 + offset])[0]
            ciphers.append(Cipher(val))

        return EncryptionCapabilities(ciphers=ciphers), length


@dataclasses.dataclass(frozen=True)
class CompressionCapabilities(NegotiateContext):
    __slots__ = ("flags", "compression_algorithms")

    flags: CompressionCapabilityFlags
    compression_algorithms: list[CompressionAlgorithm]

    def __init__(
        self,
        *,
        flags: CompressionCapabilityFlags,
        compression_algorithms: list[CompressionAlgorithm],
    ) -> None:
        super().__init__(NegotiateContextType.COMPRESSION_CAPABILITIES)
        object.__setattr__(self, "flags", flags)
        object.__setattr__(self, "compression_algorithms", compression_algorithms)

    @property
    def data(self) -> bytes:
        return b"".join(
            [
                len(self.compression_algorithms).to_bytes(2, byteorder="little"),
                b"\x00\x00",  # Padding
                self.flags.to_bytes(4, byteorder="little"),
                b"".join(
                    c.to_bytes(2, byteorder="little")
                    for c in self.compression_algorithms
                ),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: bytes | bytearray | memoryview,
        offset: int = 0,
    ) -> tuple[CompressionCapabilities, int]:
        _, length, view = _unpack_negotiate_context(
            cls.__name__,
            NegotiateContextType.COMPRESSION_CAPABILITIES,
            memoryview(data)[offset:],
        )

        algo_count = struct.unpack("<H", view[0:2])[0]
        flags = CompressionCapabilityFlags(struct.unpack("<I", view[4:8])[0])

        algos = []
        for i in range(algo_count):
            offset = i * 2
            val = struct.unpack("<H", view[8 + offset : 10 + offset])[0]
            algos.append(CompressionAlgorithm(val))

        return (
            CompressionCapabilities(flags=flags, compression_algorithms=algos),
            length,
        )


@dataclasses.dataclass(frozen=True)
class NetnameNegotiate(NegotiateContext):
    __slots__ = ("net_name",)

    net_name: str

    def __init__(
        self,
        *,
        net_name: str,
    ) -> None:
        super().__init__(NegotiateContextType.NETNAME_NEGOTIATE_CONTEXT_ID)
        object.__setattr__(self, "net_name", net_name)

    @property
    def data(self) -> bytes:
        return self.net_name.encode("utf-16-le")

    @classmethod
    def unpack(
        cls,
        data: bytes | bytearray | memoryview,
        offset: int = 0,
    ) -> tuple[NetnameNegotiate, int]:
        _, length, view = _unpack_negotiate_context(
            cls.__name__,
            NegotiateContextType.NETNAME_NEGOTIATE_CONTEXT_ID,
            memoryview(data)[offset:],
        )

        return NetnameNegotiate(net_name=bytes(view).decode("utf-16-le")), length


@dataclasses.dataclass(frozen=True)
class TransportCapabilities(NegotiateContext):
    __slots__ = ("flags",)

    flags: TransportCapabilityFlags

    def __init__(
        self,
        *,
        flags: TransportCapabilityFlags,
    ) -> None:
        super().__init__(NegotiateContextType.TRANSPORT_CAPABILITIES)
        object.__setattr__(self, "flags", flags)

    @property
    def data(self) -> bytes:
        return self.flags.to_bytes(4, byteorder="little")

    @classmethod
    def unpack(
        cls,
        data: bytes | bytearray | memoryview,
        offset: int = 0,
    ) -> tuple[TransportCapabilities, int]:
        _, length, view = _unpack_negotiate_context(
            cls.__name__,
            NegotiateContextType.TRANSPORT_CAPABILITIES,
            memoryview(data)[offset:],
        )

        flags = TransportCapabilityFlags(struct.unpack("<I", view[0:4])[0])
        return TransportCapabilities(flags=flags), length


@dataclasses.dataclass(frozen=True)
class RdmaTransformCapabilities(NegotiateContext):
    __slots__ = ("rdma_transform_ids",)

    rdma_transform_ids: list[RdmaTransformId]

    def __init__(
        self,
        *,
        rdma_transform_ids: list[RdmaTransformId],
    ) -> None:
        super().__init__(NegotiateContextType.RDMA_TRANSFORM_CAPABILITIES)
        object.__setattr__(self, "rdma_transform_ids", rdma_transform_ids)

    @property
    def data(self) -> bytes:
        return b"".join(
            [
                len(self.rdma_transform_ids).to_bytes(2, byteorder="little"),
                b"\x00\x00",  # Reserved1
                b"\x00\x00\x00\x00",  # Reserved2
                b"".join(
                    r.to_bytes(2, byteorder="little") for r in self.rdma_transform_ids
                ),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: bytes | bytearray | memoryview,
        offset: int = 0,
    ) -> tuple[RdmaTransformCapabilities, int]:
        _, length, view = _unpack_negotiate_context(
            cls.__name__,
            NegotiateContextType.RDMA_TRANSFORM_CAPABILITIES,
            memoryview(data)[offset:],
        )

        transform_count = struct.unpack("<H", view[0:2])[0]

        ids = []
        for i in range(transform_count):
            offset = i * 2
            val = struct.unpack("<H", view[8 + offset : 10 + offset])[0]
            ids.append(RdmaTransformId(val))

        return RdmaTransformCapabilities(rdma_transform_ids=ids), length


@dataclasses.dataclass(frozen=True)
class SigningCapabilities(NegotiateContext):
    __slots__ = ("signing_algorithms",)

    signing_algorithms: list[SigningAlgorithm]

    def __init__(
        self,
        *,
        signing_algorithms: list[SigningAlgorithm],
    ) -> None:
        super().__init__(NegotiateContextType.SIGNING_CAPABILITIES)
        object.__setattr__(self, "signing_algorithms", signing_algorithms)

    @property
    def data(self) -> bytes:
        return b"".join(
            [
                len(self.signing_algorithms).to_bytes(2, byteorder="little"),
                b"".join(
                    a.to_bytes(2, byteorder="little") for a in self.signing_algorithms
                ),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: bytes | bytearray | memoryview,
        offset: int = 0,
    ) -> tuple[SigningCapabilities, int]:
        _, length, view = _unpack_negotiate_context(
            cls.__name__,
            NegotiateContextType.SIGNING_CAPABILITIES,
            memoryview(data)[offset:],
        )

        algo_count = struct.unpack("<H", view[0:2])[0]

        algos = []
        for i in range(algo_count):
            offset = i * 2
            val = struct.unpack("<H", view[2 + offset : 4 + offset])[0]
            algos.append(SigningAlgorithm(val))

        return SigningCapabilities(signing_algorithms=algos), length


@dataclasses.dataclass(frozen=True)
class SMB1NegotiateRequest(SMBMessage):
    __slots__ = ("dialects",)

    dialects: list[str]

    def __init__(
        self,
        *,
        dialects: list[str],
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
        data: bytes | bytearray | memoryview,
        offset_from_header: int,
        offset: int = 0,
    ) -> SMB1NegotiateRequest:
        # FIXME
        dialects: list[str] = []

        return SMB1NegotiateRequest(dialects=dialects)


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
        data: bytes | bytearray | memoryview,
        offset_from_header: int,
        offset: int = 0,
    ) -> SMB1NegotiateResponse:
        view = memoryview(data)[offset:]

        if len(view) < 3:
            raise MalformedPacket(f"Not enough data to unpack {cls.__name__}")

        selected_index = struct.unpack("<h", view[1:3])[0]
        return SMB1NegotiateResponse(selected_index=selected_index)


@dataclasses.dataclass(frozen=True)
class NegotiateRequest(SMBMessage):
    __slots__ = (
        "dialects",
        "security_mode",
        "capabilities",
        "client_guid",
        "negotiate_contexts",
    )

    dialects: list[Dialect]
    security_mode: SecurityModes
    capabilities: Capabilities
    client_guid: uuid.UUID
    negotiate_contexts: list[NegotiateContext]

    def __init__(
        self,
        *,
        dialects: list[Dialect],
        security_mode: SecurityModes,
        capabilities: Capabilities,
        client_guid: uuid.UUID,
        negotiate_contexts: list[NegotiateContext] | None = None,
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
                context_data = context.pack()
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
        data: bytes | bytearray | memoryview,
        offset_from_header: int,
        offset: int = 0,
    ) -> NegotiateRequest:
        view = memoryview(data)[offset:]

        if len(view) < 36:
            raise MalformedPacket(f"Not enough data to unpack {cls.__name__}")

        dialect_count = struct.unpack("<H", view[2:4])[0]
        security_mode = SecurityModes(struct.unpack("<H", view[4:6])[0])
        capabilities = Capabilities(struct.unpack("<I", view[8:12])[0])
        client_guid = uuid.UUID(bytes_le=bytes(view[12:28]))
        context_offset = struct.unpack("<I", view[28:32])[0] - offset_from_header
        context_count = struct.unpack("<H", view[32:34])[0]

        end_idx = 36
        if len(view) < (36 + (dialect_count * 2)):
            raise MalformedPacket(f"{cls.__name__} dialect buffer is out of bounds")

        dialects: list[Dialect] = []
        for _ in range(dialect_count):
            dialects.append(
                Dialect(struct.unpack("<H", view[end_idx : end_idx + 2])[0])
            )
            end_idx += 2

        contexts: list[NegotiateContext] = []
        if context_count:
            end_idx = context_offset

            for idx in range(context_count):
                ctx, offset = NegotiateContext.unpack(view, offset=end_idx)
                contexts.append(ctx)

                if idx != context_count - 1:
                    # Adjust for padding
                    offset += 8 - (offset % 8 or 8)

                end_idx += offset

        return NegotiateRequest(
            dialects=dialects,
            security_mode=security_mode,
            capabilities=capabilities,
            client_guid=client_guid,
            negotiate_contexts=contexts,
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
    security_buffer: bytes | None
    negotiate_contexts: list[NegotiateContext]

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
        security_buffer: bytes | None = None,
        negotiate_contexts: list[NegotiateContext] | None = None,
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
        sec_buffer_offset = offset_from_header + 64
        negotiate_offset = 0
        padding_size = 0
        negotiate_contexts = bytearray()

        if self.negotiate_contexts:
            negotiate_offset = sec_buffer_offset + len(sec_buffer)
            padding_size = 8 - (negotiate_offset % 8 or 8)
            negotiate_offset += padding_size

            last_idx = len(self.negotiate_contexts) - 1
            for idx, context in enumerate(self.negotiate_contexts):
                context_data = context.pack()
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
        data: bytes | bytearray | memoryview,
        offset_from_header: int,
        offset: int = 0,
    ) -> NegotiateResponse:
        view = memoryview(data)[offset:]

        if len(view) < 64:
            raise MalformedPacket(f"Not enough data to unpack {cls.__name__}")

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
                raise MalformedPacket(
                    f"{cls.__name__} security buffer is out of bounds"
                )

            sec_buffer = bytes(view[sec_buffer_offset:end_idx])

        contexts: list[NegotiateContext] = []
        if context_count:
            end_idx = context_offset

            for idx in range(context_count):
                ctx, offset = NegotiateContext.unpack(view, offset=end_idx)
                contexts.append(ctx)

                if idx != context_count - 1:
                    # Adjust for padding
                    offset += 8 - (offset % 8 or 8)

                end_idx += offset

        return NegotiateResponse(
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
        )
