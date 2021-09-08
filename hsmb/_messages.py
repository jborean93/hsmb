# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import enum
import typing

from hsmb._exceptions import MalformedPacket


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


@dataclasses.dataclass(frozen=True)
class SMBMessage:
    __slots__ = ("command",)

    command: Command

    @property
    def compress_hint(self) -> typing.Optional[slice]:
        return None

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
class EchoRequest(SMBMessage):
    __slots__ = ()

    def __init__(
        self,
    ) -> None:
        super().__init__(Command.ECHO)

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
    ) -> typing.Tuple["EchoRequest", int]:
        view = memoryview(data)[offset:]
        if len(view) < 4:
            raise MalformedPacket("Echo request payload is too small")

        return EchoRequest(), 4


@dataclasses.dataclass(frozen=True)
class EchoResponse(SMBMessage):
    __slots__ = ()

    def __init__(
        self,
    ) -> None:
        super().__init__(Command.ECHO)

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
    ) -> typing.Tuple["EchoResponse", int]:
        view = memoryview(data)[offset:]
        if len(view) < 4:
            raise MalformedPacket("Echo response payload is too small")

        return EchoResponse(), 4
