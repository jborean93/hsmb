# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import enum

from hsmb._messages import Command


class HeaderFlags(enum.IntFlag):
    none = 0x00000000
    server_to_redir = 0x00000001
    async_command = 0x00000002
    related_operations = 0x00000004
    signed = 0x00000008
    priority_mask = 0x00000070
    dfs_operations = 0x10000000
    replay_operation = 0x20000000


class TransformFlags(enum.IntFlag):
    encrypted = 0x0001


@dataclasses.dataclass(frozen=True)
class SMBHeader:
    __slots__ = ("protocol_id",)

    protocol_id: bytes


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
    flags: int
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
