# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import dataclasses
import enum
import struct
import typing

from hsmb._exceptions import MalformedPacket
from hsmb._messages import Command
from hsmb._negotiate import CompressionAlgorithm


class HeaderFlags(enum.IntFlag):
    NONE = 0x00000000
    SERVER_TO_REDIR = 0x00000001
    ASYNC_COMMAND = 0x00000002
    RELATED_OPERATIONS = 0x00000004
    SIGNED = 0x00000008
    PRIORITY_MASK = 0x00000070
    DFS_OPERATIONS = 0x10000000
    REPLAY_OPERATION = 0x20000000


class SMB1HeaderFlags(enum.IntFlag):
    NONE = 0x00000000
    # Flags2
    LONG_NAMES = 0x00000001
    EAS = 0x00000002
    SMB_SECURITY_SIGNATURE = 0x00000004
    IS_COMPRESSED = 0x00000008
    SECURITY_SIGNATURE_REQUIRED = 0x00000010
    IS_LONG_NAME = 0x00000040
    REPARSE_PATH = 0x00000400
    EXTENDED_SECURITY_NEGOTIATION = 0x00000800
    DFS = 0x00001000
    PAGING_IO = 0x00002000
    NT_STATUS = 0x00004000
    UNICODE = 0x00008000
    # Flags1
    LOCK_AND_READ_OK = 0x00010000
    BUF_AVAIL = 0x00020000
    RESERVED = 0x00040000
    CASE_INSENSITIVE = 0x00080000
    CANONICALIZED_PATHS = 0x00100000
    OPLOCK = 0x00200000
    OPBATCH = 0x00400000
    REPLY = 0x00800000


class TransformFlags(enum.IntFlag):
    NONE = 0x0000
    ENCRYPTED = 0x0001


class CompressionFlags(enum.IntFlag):
    NONE = 0x0000
    CHAINED = 0x0001


@dataclasses.dataclass(frozen=True)
class SMBHeader:
    __slots__ = ("protocol_id",)

    protocol_id: bytes

    def pack(self) -> bytearray:
        raise NotImplementedError()

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset: int = 0,
    ) -> typing.Tuple["SMBHeader", int]:
        raise NotImplementedError()


@dataclasses.dataclass(frozen=True)
class SMB1Header(SMBHeader):
    __slots__ = ("command", "status", "flags", "pid", "tid", "uid", "mid", "security_features")

    command: int
    status: int
    flags: SMB1HeaderFlags
    pid: int
    tid: int
    uid: int
    mid: int
    security_features: typing.Optional[bytes]

    def __init__(
        self,
        *,
        command: int,
        status: int,
        flags: SMB1HeaderFlags,
        pid: int,
        tid: int,
        uid: int,
        mid: int,
        security_features: typing.Optional[bytes] = None,
    ) -> None:
        super().__init__(b"\xFFSMB")
        object.__setattr__(self, "command", command)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "flags", flags)
        object.__setattr__(self, "pid", pid)
        object.__setattr__(self, "tid", tid)
        object.__setattr__(self, "uid", uid)
        object.__setattr__(self, "mid", mid)
        object.__setattr__(self, "security_features", security_features)

    def pack(self) -> bytearray:
        flags1 = (self.flags & 0x00FF0000) >> 16
        flags2 = self.flags & 0x0000FFFF
        pid_high = (self.pid & 0xFFFF0000) >> 16
        pid_low = self.pid & 0x0000FFFF

        return bytearray().join(
            [
                self.protocol_id,
                self.command.to_bytes(1, byteorder="little"),
                self.status.to_bytes(4, byteorder="little"),
                flags1.to_bytes(1, byteorder="little"),
                flags2.to_bytes(2, byteorder="little"),
                pid_high.to_bytes(2, byteorder="little"),
                self.security_features or (b"\x00" * 8),
                b"\x00\x00",  # Reserved
                self.tid.to_bytes(2, byteorder="little"),
                pid_low.to_bytes(2, byteorder="little"),
                self.uid.to_bytes(2, byteorder="little"),
                self.mid.to_bytes(2, byteorder="little"),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset: int = 0,
    ) -> typing.Tuple["SMB1Header", int]:
        view = memoryview(data)[offset:]

        command = struct.unpack("B", view[4:5])[0]
        status = struct.unpack("<I", view[5:9])[0]
        flags1 = struct.unpack("B", view[9:10])[0]
        flags2 = struct.unpack("<H", view[10:12])[0]
        pid_high = struct.unpack("<H", view[12:14])[0]
        security_features = bytes(view[14:22])
        tid = struct.unpack("<H", view[24:26])[0]
        pid_low = struct.unpack("<H", view[26:28])[0]
        uid = struct.unpack("<H", view[28:30])[0]
        mid = struct.unpack("<H", view[30:32])[0]

        return (
            SMB1Header(
                command=command,
                status=status,
                flags=SMB1HeaderFlags((flags1 << 16) | flags2),
                pid=(pid_high << 16) | pid_low,
                tid=tid,
                uid=uid,
                mid=mid,
                security_features=security_features,
            ),
            32,
        )


@dataclasses.dataclass(frozen=True)
class SMB2Header(SMBHeader):
    __slots__ = (
        "credit_charge",
        "channel_sequence",
        "status",
        "command",
        "credits",
        "flags",
        "next_command",
        "message_id",
        "async_id",
        "tree_id",
        "session_id",
        "signature",
    )

    credit_charge: int
    channel_sequence: int
    status: int
    command: Command
    credits: int
    flags: HeaderFlags
    next_command: int
    message_id: int
    async_id: int
    tree_id: int
    session_id: int
    signature: bytes

    def __init__(
        self,
        *,
        credit_charge: int,
        channel_sequence: int,
        status: int,
        command: Command,
        credits: int,
        flags: HeaderFlags,
        next_command: int,
        message_id: int,
        async_id: int,
        tree_id: int,
        session_id: int,
        signature: bytes,
    ) -> None:
        super().__init__(b"\xFESMB")
        object.__setattr__(self, "credit_charge", credit_charge)
        object.__setattr__(self, "channel_sequence", channel_sequence)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "command", command)
        object.__setattr__(self, "credits", credits)
        object.__setattr__(self, "flags", flags)
        object.__setattr__(self, "next_command", next_command)
        object.__setattr__(self, "message_id", message_id)
        object.__setattr__(self, "async_id", async_id)
        object.__setattr__(self, "tree_id", tree_id)
        object.__setattr__(self, "session_id", session_id)
        object.__setattr__(self, "signature", signature)

    def pack(self) -> bytearray:
        status = self.status
        if self.channel_sequence:
            status = self.channel_sequence

        # The async and sync header is the same except the async header has an 8 byte AsyncId field whereas the sync
        # header has a Reserved + TreeId field. Use the specified flags to differenciate between the 2.
        if self.flags & HeaderFlags.ASYNC_COMMAND:
            async_tree_id_field = self.async_id.to_bytes(8, byteorder="little")
        else:
            async_tree_id_field = b"\x00\x00\x00\x00" + self.tree_id.to_bytes(4, byteorder="little")

        return bytearray().join(
            [
                self.protocol_id,
                b"\x40\x00",  # StructureSize (64)
                self.credit_charge.to_bytes(2, byteorder="little"),
                status.to_bytes(4, byteorder="little"),
                self.command.value.to_bytes(2, byteorder="little"),
                self.credits.to_bytes(2, byteorder="little"),
                self.flags.value.to_bytes(4, byteorder="little"),
                self.next_command.to_bytes(4, byteorder="little"),
                self.message_id.to_bytes(8, byteorder="little"),
                async_tree_id_field,
                self.session_id.to_bytes(8, byteorder="little"),
                self.signature or (b"\x00" * 16),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset: int = 0,
    ) -> typing.Tuple["SMB2Header", int]:
        view = memoryview(data)[offset:]

        credit_charge = struct.unpack("<H", view[6:8])[0]
        channel_sequence = struct.unpack("<H", view[8:10])[0]
        status = struct.unpack("<I", view[8:12])[0]
        command = Command(struct.unpack("<H", view[12:14])[0])
        credits = struct.unpack("<H", view[14:16])[0]
        flags = HeaderFlags(struct.unpack("<I", view[16:20])[0])
        next_command = struct.unpack("<I", view[20:24])[0]
        message_id = struct.unpack("<Q", view[24:32])[0]

        if flags & HeaderFlags.ASYNC_COMMAND:
            async_id = struct.unpack("<Q", view[32:40])[0]
            tree_id = 0
        else:
            async_id = 0
            tree_id = struct.unpack("<I", view[36:40])[0]

        session_id = struct.unpack("<Q", view[40:48])[0]
        signature = bytes(view[48:64])

        return (
            SMB2Header(
                credit_charge=credit_charge,
                channel_sequence=channel_sequence,
                status=status,
                command=command,
                credits=credits,
                flags=flags,
                next_command=next_command,
                message_id=message_id,
                async_id=async_id,
                tree_id=tree_id,
                session_id=session_id,
                signature=signature,
            ),
            64,
        )


@dataclasses.dataclass(frozen=True)
class TransformHeader(SMBHeader):
    __slots__ = ("signature", "nonce", "original_message_size", "flags", "session_id")

    signature: bytes
    nonce: bytes
    original_message_size: int
    flags: TransformFlags
    session_id: int

    def __init__(
        self,
        *,
        signature: bytes,
        nonce: bytes,
        original_message_size: int,
        flags: TransformFlags,
        session_id: int,
    ) -> None:
        super().__init__(b"\xFDSMB")
        object.__setattr__(self, "signature", signature)
        object.__setattr__(self, "nonce", nonce)
        object.__setattr__(self, "original_message_size", original_message_size)
        object.__setattr__(self, "flags", flags)
        object.__setattr__(self, "session_id", session_id)

    def pack(self) -> bytearray:
        return bytearray().join(
            [
                self.protocol_id,
                self.signature,
                self.nonce,
                self.original_message_size.to_bytes(4, byteorder="little"),
                b"\x00\x00",  # Reserved
                self.flags.value.to_bytes(2, byteorder="little"),
                self.session_id.to_bytes(8, byteorder="little"),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset: int = 0,
    ) -> typing.Tuple["TransformHeader", int]:
        view = memoryview(data)[offset:]

        signature = bytes(view[4:20])
        nonce = bytes(view[20:36])
        original_message_size = struct.unpack("<I", view[36:40])[0]
        flags = TransformFlags(struct.unpack("<H", view[42:44])[0])
        session_id = struct.unpack("<Q", view[44:52])[0]

        return (
            TransformHeader(
                signature=signature,
                nonce=nonce,
                original_message_size=original_message_size,
                flags=flags,
                session_id=session_id,
            ),
            52,
        )


@dataclasses.dataclass(frozen=True)
class CompressionTransform(SMBHeader):
    __slots__ = "original_compressed_segment_size"

    original_compressed_segment_size: int

    def __init__(
        self,
        *,
        original_compressed_segment_size: int,
    ) -> None:
        super().__init__(b"\xFCSMB")
        object.__setattr__(self, "original_compressed_segment_size", original_compressed_segment_size)

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset: int = 0,
    ) -> typing.Tuple["CompressionTransform", int]:
        view = memoryview(data)[offset:]

        if len(view) < 12:
            raise MalformedPacket("Compression transform header payload is too small")

        flags = CompressionFlags(struct.unpack("<H", view[10:12])[0])
        if flags & CompressionFlags.CHAINED:
            return CompressionTransformChained.unpack(data, offset)

        else:
            return CompressionTransformUnchained.unpack(data, offset)


@dataclasses.dataclass(frozen=True)
class CompressionTransformUnchained(CompressionTransform):

    __slots__ = ("compression_algorithm", "flags", "offset", "data")

    compression_algorithm: CompressionAlgorithm
    flags: CompressionFlags
    offset: int
    data: memoryview

    def __init__(
        self,
        *,
        original_compressed_segment_size: int,
        compression_algorithm: CompressionAlgorithm,
        flags: CompressionFlags,
        offset: int,
        data: memoryview,
    ) -> None:
        super().__init__(original_compressed_segment_size=original_compressed_segment_size)
        object.__setattr__(self, "compression_algorithm", compression_algorithm)
        object.__setattr__(self, "flags", flags)
        object.__setattr__(self, "offset", offset)
        object.__setattr__(self, "data", data)

    def pack(self) -> bytearray:
        return bytearray().join(
            [
                self.protocol_id,
                self.original_compressed_segment_size.to_bytes(4, byteorder="little"),
                self.compression_algorithm.to_bytes(2, byteorder="little"),
                self.flags.to_bytes(2, byteorder="little"),
                self.offset.to_bytes(4, byteorder="little"),
                bytes(self.data),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset: int = 0,
    ) -> typing.Tuple["CompressionTransformUnchained", int]:
        view = memoryview(data)[offset:]

        if len(view) < 16:
            raise MalformedPacket("Compression transform header payload is too small")

        original_compressed_segment_size = struct.unpack("<I", view[4:8])[0]
        compression_algorithm = CompressionAlgorithm(struct.unpack("<H", view[8:10])[0])
        flags = CompressionFlags(struct.unpack("<H", view[10:12])[0])
        offset = struct.unpack("<I", view[12:16])[0]

        return (
            CompressionTransformUnchained(
                original_compressed_segment_size=original_compressed_segment_size,
                compression_algorithm=compression_algorithm,
                flags=flags,
                offset=offset,
                data=view[16:],
            ),
            len(view),
        )


@dataclasses.dataclass(frozen=True)
class CompressionTransformChained(CompressionTransform):

    __slots__ = ("compression_payload_header",)

    compression_payload_header: typing.List["CompressionChainedPayloadHeader"]

    def __init__(
        self,
        *,
        original_compressed_segment_size: int,
        compression_payload_header: typing.List["CompressionChainedPayloadHeader"],
    ) -> None:
        super().__init__(original_compressed_segment_size=original_compressed_segment_size)
        object.__setattr__(self, "compression_payload_header", compression_payload_header)

    def pack(self) -> bytearray:
        buffer = bytearray()
        return bytearray().join(
            [
                self.protocol_id,
                self.original_compressed_segment_size.to_bytes(4, byteorder="little"),
                buffer,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset: int = 0,
    ) -> typing.Tuple["CompressionTransformChained", int]:
        view = memoryview(data)[offset:]

        if len(view) < 16:
            raise MalformedPacket("Compression transform header payload is too small")

        original_compressed_segment_size = struct.unpack("<I", view[4:8])[0]
        payloads: typing.List["CompressionChainedPayloadHeader"] = []
        end_idx = 8

        while end_idx < len(view):
            payload, new_offset = CompressionChainedPayloadHeader.unpack(view, end_idx)
            payloads.append(payload)
            end_idx += new_offset

        return (
            CompressionTransformChained(
                original_compressed_segment_size=original_compressed_segment_size,
                compression_payload_header=payloads,
            ),
            end_idx,
        )


@dataclasses.dataclass(frozen=True)
class CompressionChainedPayloadHeader:
    __slots__ = ("compression_algorithm", "flags", "data")

    compression_algorithm: CompressionAlgorithm
    flags: CompressionFlags
    data: memoryview

    def __init__(
        self,
        *,
        compression_algorithm: CompressionAlgorithm,
        flags: CompressionFlags,
        data: memoryview,
    ) -> None:
        object.__setattr__(self, "compression_algorithm", compression_algorithm)
        object.__setattr__(self, "flags", flags)
        object.__setattr__(self, "data", data)

    def pack(self) -> bytearray:
        return bytearray().join(
            [
                self.compression_algorithm.to_bytes(2, byteorder="little"),
                self.flags.to_bytes(2, byteorder="little"),
                len(self.data).to_bytes(4, byteorder="little"),
                bytes(self.data),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset: int = 0,
    ) -> typing.Tuple["CompressionChainedPayloadHeader", int]:
        view = memoryview(data[offset:])

        if len(view) < 8:
            raise MalformedPacket("Compression transform header payload is too small")

        compression_algorithm = CompressionAlgorithm(struct.unpack("<H", view[0:2])[0])
        flags = CompressionFlags(struct.unpack("<H", view[2:4])[0])
        length = struct.unpack("<I", view[4:8])[0]

        if len(view) < 8 + length:
            raise MalformedPacket("Compression transform chained header payload out of bounds")
        end_idx = 8 + length

        return (
            CompressionChainedPayloadHeader(
                compression_algorithm=compression_algorithm,
                flags=flags,
                data=view[8:end_idx],
            ),
            end_idx,
        )


@dataclasses.dataclass(frozen=True)
class CompressionPatternPayloadV1:

    __slots__ = ("pattern", "repetitions")

    pattern: int
    repetitions: int

    def __init__(
        self,
        *,
        pattern: int,
        repetitions: int,
    ) -> None:
        object.__setattr__(self, "pattern", pattern)
        object.__setattr__(self, "repetitions", repetitions)

    def pack(self) -> bytearray:
        return bytearray().join(
            [
                self.pattern.to_bytes(1, byteorder="little"),
                b"\x00\x00\x00",  # Reserved1 + Reserved2
                self.repetitions.to_bytes(4, byteorder="little"),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset: int = 0,
    ) -> typing.Tuple["CompressionPatternPayloadV1", int]:
        view = memoryview(data)[offset:]

        if len(view) < 8:
            raise MalformedPacket("Compression pattern payload v1 is too small")

        pattern = struct.unpack("<B", view[:1])[0]
        repetitions = struct.unpack("<I", view[4:8])[0]

        return cls(pattern=pattern, repetitions=repetitions), 8


def unpack_header(
    data: typing.Union[bytes, bytearray, memoryview],
) -> typing.Tuple[SMBHeader, int]:
    """Unpack the SMB Header bytes.

    Unpacks the SMB header bytes value to the object it represents. The
    value is unpacked according to the protocol id specified in the first 4
    bytes of the data.

    Args:
        data: The data to unpack.

    Returns:
        Tuple[SMBHeader, int]: The unpacked header and the length of the
        header that was unpacked.
    """
    view = memoryview(data)

    protocol_id = bytes(view[:4])
    header_cls: typing.Type[SMBHeader]
    if protocol_id == b"\xFFSMB":
        header_cls = SMB1Header
    elif protocol_id == b"\xFESMB":
        header_cls = SMB2Header
    elif protocol_id == b"\xFDSMB":
        header_cls = TransformHeader
    elif protocol_id == b"\xFCSMB":
        header_cls = CompressionTransform
    else:
        raise ValueError(f"Unknown SMB Header protocol {base64.b16encode(protocol_id).decode()}")

    return header_cls.unpack(data)
