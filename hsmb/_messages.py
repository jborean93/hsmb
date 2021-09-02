# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import dataclasses
import enum
import struct
import typing


class Command(enum.IntEnum):
    NEGOTIATE = 0x0000
    SESSION_SETUP = 0x0001
    LOGOFF = 0x0002
    TREE_CONNECT = 0x0003
    TREE_DISCONNECT = 0x0004
    CREATE = 0x0005
    CLOSE = 0x0006
    FLUSH = 0x0007
    READ = 0x0008
    WRITE = 0x0009
    LOCK = 0x000A
    IOCTL = 0x000B
    CANCEL = 0x000C
    ECHO = 0x000D
    QUERY_DIRECTORY = 0x000E
    CHANGE_NOTIFY = 0x000F
    QUERY_INFO = 0x0010
    SET_INFO = 0x0011
    OPLOCK_BREAK = 0x0011
    SMB1_NEGOTIATE = 0x0072


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


@dataclasses.dataclass(frozen=True)
class SMBMessage:
    __slots__ = ("command",)

    command: Command

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        raise NotImplementedError()

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["SMBMessage", int]:
        raise NotImplementedError()


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
    else:
        raise ValueError(f"Unknown SMB Header protocol {base64.b16encode(protocol_id).decode()}")

    return header_cls.unpack(data)
