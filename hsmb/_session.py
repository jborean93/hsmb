# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import enum
import struct
import typing

from hsmb._exceptions import MalformedPacket
from hsmb._messages import MESSAGES, Command, SMBMessage
from hsmb._negotiate import Capabilities, SecurityModes


class SessionFlags(enum.IntFlag):
    IS_GUEST = 0x0001
    IS_NULL = 0x0002
    ENCRYPT_DATA = 0x0004


class SessionSetupFlags(enum.IntFlag):
    NONE = 0x0
    BINDING = 0x01


@dataclasses.dataclass(frozen=True)
class SessionSetupRequest(SMBMessage):
    __slots__ = ("flags", "security_mode", "capabilities", "channel", "previous_session_id", "security_buffer")

    flags: SessionSetupFlags
    security_mode: SecurityModes
    capabilities: Capabilities
    channel: int
    previous_session_id: int
    security_buffer: bytes

    def __init__(
        self,
        *,
        flags: SessionSetupFlags,
        security_mode: SecurityModes,
        capabilities: Capabilities,
        channel: int,
        previous_session_id: int,
        security_buffer: bytes,
    ) -> None:
        super().__init__(Command.SESSION_SETUP)
        object.__setattr__(self, "flags", flags)
        object.__setattr__(self, "security_mode", security_mode)
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "channel", channel)
        object.__setattr__(self, "previous_session_id", previous_session_id)
        object.__setattr__(self, "security_buffer", security_buffer)

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        return bytearray().join(
            [
                b"\x19\x00",  # StructureSize(25)
                self.flags.to_bytes(1, byteorder="little"),
                self.security_mode.to_bytes(1, byteorder="little"),
                self.capabilities.to_bytes(4, byteorder="little"),
                self.channel.to_bytes(4, byteorder="little"),
                (offset_from_header + 24).to_bytes(2, byteorder="little"),
                len(self.security_buffer).to_bytes(2, byteorder="little"),
                self.previous_session_id.to_bytes(8, byteorder="little"),
                self.security_buffer,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["SessionSetupRequest", int]:
        view = memoryview(data)[offset:]

        if len(view) < 24:
            raise MalformedPacket("Session setup request payload is too small")

        flags = SessionSetupFlags(struct.unpack("<B", view[2:3])[0])
        security_mode = SecurityModes(struct.unpack("<B", view[3:4])[0])
        capabilities = Capabilities(struct.unpack("<I", view[4:8])[0])
        channel = struct.unpack("<I", view[8:12])[0]
        sec_offset = struct.unpack("<H", view[12:14])[0] - offset_from_header
        sec_length = struct.unpack("<H", view[14:16])[0]
        previous_session_id = struct.unpack("<Q", view[16:24])[0]

        if len(view) < (sec_offset + sec_length):
            raise MalformedPacket("Session setup request sec buffer is out of bounds")
        buffer = bytes(view[sec_offset : sec_offset + sec_length])

        return (
            SessionSetupRequest(
                flags=flags,
                security_mode=security_mode,
                capabilities=capabilities,
                channel=channel,
                previous_session_id=previous_session_id,
                security_buffer=buffer,
            ),
            sec_offset + sec_length,
        )


@dataclasses.dataclass(frozen=True)
class SessionSetupResponse(SMBMessage):
    __slots__ = ("session_flags", "security_buffer")

    session_flags: SessionFlags
    security_buffer: bytes

    def __init__(
        self,
        *,
        session_flags: SessionFlags,
        security_buffer: bytes,
    ) -> None:
        super().__init__(Command.SESSION_SETUP)
        object.__setattr__(self, "session_flags", session_flags)
        object.__setattr__(self, "security_buffer", security_buffer)

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        return bytearray().join(
            [
                b"\x09\x00",  # StructureSize(9)
                self.session_flags.to_bytes(2, byteorder="little"),
                (offset_from_header + 8).to_bytes(2, byteorder="little"),
                len(self.security_buffer).to_bytes(2, byteorder="little"),
                self.security_buffer,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["SessionSetupResponse", int]:
        view = memoryview(data)[offset:]

        if len(view) < 8:
            raise MalformedPacket("Session setup response payload is too small")

        session_flags = SessionFlags(struct.unpack("<H", view[2:4])[0])
        sec_offset = struct.unpack("<H", view[4:6])[0] - offset_from_header
        sec_length = struct.unpack("<H", view[6:8])[0]

        if len(view) < (sec_offset + sec_length):
            raise MalformedPacket("Session setup response sec buffer is out of bounds")
        buffer = bytes(view[sec_offset : sec_offset + sec_length])

        return SessionSetupResponse(session_flags=session_flags, security_buffer=buffer), sec_offset + sec_length


@dataclasses.dataclass(frozen=True)
class LogoffRequest(SMBMessage):
    __slots__ = ()

    def __init__(
        self,
    ) -> None:
        super().__init__(Command.LOGOFF)

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        return bytearray(b"\x04\x00\x00\x00")

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["LogoffRequest", int]:
        view = memoryview(data)[offset:]
        if len(view) < 4:
            raise MalformedPacket("Logoff request payload is too small")

        return LogoffRequest(), 4


@dataclasses.dataclass(frozen=True)
class LogoffResponse(SMBMessage):
    __slots__ = ()

    def __init__(
        self,
    ) -> None:
        super().__init__(Command.LOGOFF)

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        return bytearray(b"\x04\x00\x00\x00")

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["LogoffResponse", int]:
        view = memoryview(data)[offset:]
        if len(view) < 4:
            raise MalformedPacket("Logoff response payload is too small")

        return LogoffResponse(), 4


MESSAGES[Command.SESSION_SETUP] = (SessionSetupRequest, SessionSetupResponse)
MESSAGES[Command.LOGOFF] = (LogoffRequest, LogoffResponse)
