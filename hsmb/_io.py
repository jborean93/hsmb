# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import enum
import struct
import typing

from hsmb._exceptions import MalformedPacket
from hsmb._messages import Command, SMBMessage


class ReadFlags(enum.IntFlag):
    NONE = 0x00
    READ_UNBUFFERED = 0x01
    REQUEST_COMPRESSED = 0x02


class ReadChannel(enum.IntEnum):
    NONE = 0x00000000
    RDMA_V1 = 0x00000001
    RDMA_V1_INVALIDATE = 0x00000002


@dataclasses.dataclass(frozen=True)
class FlushRequest(SMBMessage):
    __slots__ = ("file_id",)

    file_id: bytes

    def __init__(
        self,
        *,
        file_id: bytes,
    ) -> None:
        super().__init__(Command.FLUSH)
        object.__setattr__(self, "file_id", file_id)

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        return bytearray().join(
            [
                b"\x18\x00",  # StructureSize(24)
                b"\x00\x00",  # Reserved1
                b"\x00\x00\x00\x00",  # Reserved2
                self.file_id,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["FlushRequest", int]:
        view = memoryview(data)[offset:]

        if len(view) < 24:
            raise MalformedPacket("Flush request payload is too small")

        return cls(file_id=bytes(view[8:24])), 24


@dataclasses.dataclass(frozen=True)
class FlushResponse(SMBMessage):
    __slots__ = ()

    def __init__(
        self,
    ) -> None:
        super().__init__(Command.FLUSH)

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
    ) -> typing.Tuple["FlushResponse", int]:
        view = memoryview(data)[offset:]
        if len(view) < 4:
            raise MalformedPacket("Flush response payload is too small")

        return cls(), 4


@dataclasses.dataclass(frozen=True)
class ReadRequest(SMBMessage):
    __slot__ = (
        "flags",
        "length",
        "offset",
        "file_id",
        "minimum_count",
        "channel",
        "remaining_bytes",
        "read_channel_info",
    )

    flags: ReadFlags
    length: int
    offset: int
    file_id: bytes
    minimum_count: int
    channel: ReadChannel
    remaining_bytes: int
    read_channel_info: typing.Optional[bytes]

    def __init__(
        self,
        *,
        flags: ReadFlags,
        length: int,
        offset: int,
        file_id: bytes,
        minimum_count: int,
        channel: ReadChannel,
        remaining_bytes: int,
        read_channel_info: typing.Optional[bytes] = None,
    ) -> None:
        super().__init__(Command.READ)
        object.__setattr__(self, "flags", flags)
        object.__setattr__(self, "length", length)
        object.__setattr__(self, "offset", offset)
        object.__setattr__(self, "file_id", file_id)
        object.__setattr__(self, "minimum_count", minimum_count)
        object.__setattr__(self, "channel", channel)
        object.__setattr__(self, "remaining_bytes", remaining_bytes)
        object.__setattr__(self, "read_channel_info", read_channel_info)

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        return bytearray().join(
            [
                b"\x31\x00",
                b"\x00",  # Padding
                self.flags.to_bytes(1, byteorder="little"),
                self.length.to_bytes(4, byteorder="little"),
                self.offset.to_bytes(8, byteorder="little"),
                self.file_id,
                self.minimum_count.to_bytes(4, byteorder="little"),
                self.channel.to_bytes(4, byteorder="little"),
                self.remaining_bytes.to_bytes(4, byteorder="little"),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["ReadRequest", int]:
        view = memoryview(data)[offset:]
        if len(view) < 4:
            raise MalformedPacket("Flush response payload is too small")

        return cls(), 4
