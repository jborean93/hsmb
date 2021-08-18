# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import enum
import struct
import typing

from hsmb._messages import Command


class HeaderFlags(enum.IntFlag):
    NONE = 0x00000000
    SERVER_TO_REDIR = 0x00000001
    ASYNC_COMMAND = 0x00000002
    RELATED_OPERATIONS = 0x00000004
    SIGNED = 0x00000008
    PRIORITY_MASK = 0x00000070
    DFS_OPERATIONS = 0x10000000
    REPLAY_OPERATION = 0x20000000


class TransformFlags(enum.IntFlag):
    ENCRYPTED = 0x0001


@dataclasses.dataclass(frozen=True)
class SMBHeader:
    __slots__ = ("protocol_id",)

    protocol_id: bytes

    def pack(self) -> bytes:
        raise NotImplementedError()

    @classmethod
    def unpack(cls, data: typing.Union[bytes, bytearray, memoryview]) -> "SMBHeader":
        raise NotImplementedError()


@dataclasses.dataclass(frozen=True)
class PacketHeaderAsync(SMBHeader):
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
        object.__setattr__(self, "session_id", session_id)
        object.__setattr__(self, "signature", signature)

    def pack(self) -> bytes:
        status = self.status
        if self.channel_sequence:
            status = self.channel_sequence

        return b"".join(
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
                self.async_id.to_bytes(8, byteorder="little"),
                self.session_id.to_bytes(8, byteorder="little"),
                self.signature or (b"\x00" * 16),
            ]
        )

    @classmethod
    def unpack(cls, data: typing.Union[bytes, bytearray, memoryview]) -> "PacketHeaderAsync":
        view = memoryview(data)

        credit_charge = struct.unpack("<H", view[6:8])[0]
        channel_sequence = struct.unpack("<H", view[8:10])[0]
        status = struct.unpack("<I", view[8:12])[0]
        command = Command(struct.unpack("<H", view[12:14])[0])
        credits = struct.unpack("<H", view[14:16])[0]
        flags = HeaderFlags(struct.unpack("<I", view[16:20])[0])
        next_command = struct.unpack("<I", view[20:24])[0]
        message_id = status.unpack("<Q", view[24:32])[0]
        async_id = status.unpack("<Q", view[32:40])[0]
        session_id = struct.unpack("<Q", view[40:48])[0]
        signature = bytes(view[48:64])

        return PacketHeaderAsync(
            credit_charge=credit_charge,
            channel_sequence=channel_sequence,
            status=status,
            command=command,
            credits=credits,
            flags=flags,
            next_command=next_command,
            message_id=message_id,
            async_id=async_id,
            session_id=session_id,
            signature=signature,
        )


@dataclasses.dataclass(frozen=True)
class PacketHeaderSync(SMBHeader):
    __slots__ = (
        "credit_charge",
        "channel_sequence",
        "status",
        "command",
        "credits",
        "flags",
        "next_command",
        "message_id",
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
        object.__setattr__(self, "tree_id", tree_id)
        object.__setattr__(self, "session_id", session_id)
        object.__setattr__(self, "signature", signature)

    def pack(self) -> bytes:
        status = self.status
        if self.channel_sequence:
            status = self.channel_sequence

        return b"".join(
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
                b"\x00\x00\x00\x00",  # Reserved
                self.tree_id.to_bytes(4, byteorder="little"),
                self.session_id.to_bytes(8, byteorder="little"),
                self.signature or (b"\x00" * 16),
            ]
        )

    @classmethod
    def unpack(cls, data: typing.Union[bytes, bytearray, memoryview]) -> "PacketHeaderSync":
        view = memoryview(data)

        credit_charge = struct.unpack("<H", view[6:8])[0]
        channel_sequence = struct.unpack("<H", view[8:10])[0]
        status = struct.unpack("<I", view[8:12])[0]
        command = Command(struct.unpack("<H", view[12:14])[0])
        credits = struct.unpack("<H", view[14:16])[0]
        flags = HeaderFlags(struct.unpack("<I", view[16:20])[0])
        next_command = struct.unpack("<I", view[20:24])[0]
        message_id = status.unpack("<Q", view[24:32])[0]
        tree_id = status.unpack("<I", view[36:40])[0]
        session_id = struct.unpack("<Q", view[40:48])[0]
        signature = bytes(view[48:64])

        return PacketHeaderSync(
            credit_charge=credit_charge,
            channel_sequence=channel_sequence,
            status=status,
            command=command,
            credits=credits,
            flags=flags,
            next_command=next_command,
            message_id=message_id,
            tree_id=tree_id,
            session_id=session_id,
            signature=signature,
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

    def pack(self) -> bytes:
        return b"".join(
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
    def unpack(cls, data: typing.Union[bytes, bytearray, memoryview]) -> "TransformHeader":
        view = memoryview(data)

        signature = bytes(view[4:20])
        nonce = bytes(view[20:36])
        original_message_size = struct.unpack("<I", view[36:40])[0]
        flags = TransformFlags(struct.unpack("<H", view[42:44])[0])
        session_id = struct.unpack("<Q", view[44:52])[0]

        return TransformHeader(
            signature=signature,
            nonce=nonce,
            original_message_size=original_message_size,
            flags=flags,
            session_id=session_id,
        )
