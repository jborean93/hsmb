# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import enum
import struct
import typing

from hsmb._exceptions import MalformedPacket
from hsmb._messages import Command, SMBMessage


class ReadChannel(enum.IntEnum):
    NONE = 0x00000000
    RDMA_V1 = 0x00000001
    RDMA_V1_INVALIDATE = 0x00000002


class ReadRequestFlags(enum.IntFlag):
    NONE = 0x00
    READ_UNBUFFERED = 0x01
    REQUEST_COMPRESSED = 0x02


class ReadResponseFlags(enum.IntFlag):
    NONE = 0x00000000
    RDMS_TRANSFORM = 0x00000001


class WriteChannel(enum.IntEnum):
    NONE = 0x00000000
    RDMA_V1 = 0x00000001
    RDMA_V1_INVALIDATE = 0x00000002
    RDMA_TRANSFORM = 0x00000003


class WriteFlags(enum.IntFlag):
    NONE = 0x00000000
    WRITE_THROUGH = 0x00000001
    WRITE_UNBUFFERED = 0x00000002


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
        "padding",
    )

    flags: ReadRequestFlags
    length: int
    offset: int
    file_id: bytes
    minimum_count: int
    channel: ReadChannel
    remaining_bytes: int
    read_channel_info: typing.Optional[bytes]
    padding: int

    def __init__(
        self,
        *,
        flags: ReadRequestFlags,
        length: int,
        offset: int,
        file_id: bytes,
        minimum_count: int,
        channel: ReadChannel,
        remaining_bytes: int,
        read_channel_info: typing.Optional[bytes] = None,
        padding: int = 80,
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
        object.__setattr__(self, "padding", padding)

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        buffer = bytearray()

        read_channel_offset = 0
        read_channel_length = 0
        if self.read_channel_info:
            read_channel_length = len(self.read_channel_info)
            read_channel_offset = offset_from_header + 48
            buffer += self.read_channel_info

        return bytearray().join(
            [
                b"\x31\x00",  # StructureSize(49)
                self.padding.to_bytes(1, byteorder="little"),
                self.flags.to_bytes(1, byteorder="little"),
                self.length.to_bytes(4, byteorder="little"),
                self.offset.to_bytes(8, byteorder="little"),
                self.file_id,
                self.minimum_count.to_bytes(4, byteorder="little"),
                self.channel.to_bytes(4, byteorder="little"),
                self.remaining_bytes.to_bytes(4, byteorder="little"),
                read_channel_offset.to_bytes(2, byteorder="little"),
                read_channel_length.to_bytes(2, byteorder="little"),
                buffer or b"\x00",
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
        if len(view) < 49:
            raise MalformedPacket("Read request payload is too small")

        padding = struct.unpack("<B", view[2:3])[0]
        flags = ReadRequestFlags(struct.unpack("<B", view[3:4])[0])
        length = struct.unpack("<I", view[4:8])[0]
        offset = struct.unpack("<Q", view[8:16])[0]
        file_id = bytes(view[16:32])
        minimum_count = struct.unpack("<I", view[32:36])[0]
        channel = ReadChannel(struct.unpack("<I", view[36:40])[0])
        remaining_bytes = struct.unpack("<I", view[40:44])[0]
        read_channel_offset = struct.unpack("<H", view[44:46])[0] - offset_from_header
        read_channel_length = struct.unpack("<H", view[46:48])[0]
        read_channel = None
        end_idx = 48

        if read_channel_length:
            end_idx = read_channel_offset + read_channel_length
            if len(view) < end_idx:
                raise MalformedPacket("Read request read channel info buffer out of bound")

            read_channel = bytes(view[read_channel_offset:end_idx])
        else:
            end_idx += 1

        return (
            cls(
                flags=flags,
                length=length,
                offset=offset,
                file_id=file_id,
                minimum_count=minimum_count,
                channel=channel,
                remaining_bytes=remaining_bytes,
                read_channel_info=read_channel,
                padding=padding,
            ),
            end_idx,
        )


@dataclasses.dataclass(frozen=True)
class ReadResponse(SMBMessage):

    __slots__ = ("data_remaining", "flags", "data")

    data_remaining: int
    flags: ReadResponseFlags
    data: bytes

    def __init__(
        self,
        *,
        data_remaining: int,
        flags: ReadResponseFlags,
        data: bytes,
    ) -> None:
        super().__init__(Command.READ)
        object.__setattr__(self, "data_remaining", data_remaining)
        object.__setattr__(self, "flags", flags)
        object.__setattr__(self, "data", data)

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        data_offset = 0  # FIXME
        return bytearray().join(
            [
                b"\x11\x00",  # StructureSize(17)
                data_offset.to_bytes(1, byteorder="little"),
                b"\x00",  # Reserved
                len(self.data).to_bytes(4, byteorder="little"),
                self.data_remaining.to_bytes(4, byteorder="little"),
                self.flags.to_bytes(4, byteorder="little"),
                self.data or b"\x00",
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["ReadResponse", int]:
        view = memoryview(data)[offset:]
        if len(view) < 17:
            raise MalformedPacket("Read response payload is too small")

        data_offset = struct.unpack("<B", view[2:3])[0] - offset_from_header
        data_length = struct.unpack("<I", view[4:8])[0]
        data_remaining = struct.unpack("<I", view[8:12])[0]
        flags = ReadResponseFlags(struct.unpack("<I", view[12:16])[0])
        data = b""

        if data_length:
            end_idx = data_offset + data_length
            if len(view) < end_idx:
                raise MalformedPacket("Read response data buffer is out of bounds")

            data = bytes(view[data_offset:end_idx])

        else:
            end_idx = 17

        return (
            cls(
                data_remaining=data_remaining,
                flags=flags,
                data=data,
            ),
            end_idx,
        )


@dataclasses.dataclass(frozen=True)
class WriteRequest(SMBMessage):

    __slots__ = ("offset", "file_id", "channel", "remaining_bytes", "flags", "data", "write_channel_info")

    offset: int
    file_id: bytes
    channel: WriteChannel
    remaining_bytes: int
    flags: WriteFlags
    data: typing.Union[bytes, bytearray, memoryview]
    write_channel_info: typing.Optional[bytes]

    def __init__(
        self,
        *,
        offset: int,
        file_id: bytes,
        channel: WriteChannel,
        remaining_bytes: int,
        flags: WriteFlags,
        data: typing.Union[bytes, bytearray, memoryview],
        write_channel_info: typing.Optional[bytes] = None,
    ) -> None:
        super().__init__(Command.WRITE)
        object.__setattr__(self, "offset", offset)
        object.__setattr__(self, "file_id", file_id)
        object.__setattr__(self, "channel", channel)
        object.__setattr__(self, "remaining_bytes", remaining_bytes)
        object.__setattr__(self, "flags", flags)
        object.__setattr__(self, "data", data)
        object.__setattr__(self, "write_channel_info", write_channel_info)

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        buffer = bytearray()
        data_offset = 0
        if self.data:
            data_offset = 48 + offset_from_header
            buffer += self.data

        write_channel_offset = 0
        write_channel_length = 0
        if self.write_channel_info:
            write_channel_length = len(self.write_channel_info)
            write_channel_offset = 48 + offset_from_header + len(buffer)
            buffer += self.write_channel_info

        return bytearray().join(
            [
                b"\x31\x00",  # StructureSize(49)
                data_offset.to_bytes(2, byteorder="little"),
                len(self.data).to_bytes(4, byteorder="little"),
                self.offset.to_bytes(8, byteorder="little"),
                self.file_id,
                self.channel.to_bytes(4, byteorder="little"),
                self.remaining_bytes.to_bytes(4, byteorder="little"),
                write_channel_offset.to_bytes(2, byteorder="little"),
                write_channel_length.to_bytes(2, byteorder="little"),
                self.flags.to_bytes(4, byteorder="little"),
                buffer,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["WriteRequest", int]:
        view = memoryview(data)[offset:]
        if len(view) < 49:
            raise MalformedPacket("Write request payload is too small")

        data_offset = struct.unpack("<H", view[2:4])[0] - offset_from_header
        length = struct.unpack("<I", view[4:8])[0]
        offset = struct.unpack("<Q", view[8:16])[0]
        file_id = bytes(view[16:32])
        channel = WriteChannel(struct.unpack("<I", view[32:36])[0])
        remaining_bytes = struct.unpack("<I", view[36:40])[0]
        write_channel_offset = struct.unpack("<H", view[40:42])[0]
        write_channel_length = struct.unpack("<H", view[42:44])[0]
        flags = WriteFlags(struct.unpack("<I", view[44:48])[0])
        data = b""
        write_channel = None

        data_end = 0
        if length:
            data_end = data_offset + length
            if len(view) < data_end:
                raise MalformedPacket("Write request data buffer is out of bounds")

            data = bytes(view[data_offset:data_end])

        write_channel_end = 0
        if write_channel_length:
            write_channel_end = write_channel_offset + write_channel_length
            if len(view) < write_channel_end:
                raise MalformedPacket("Write request write channel buffer if out of bounds")

            write_channel = bytes(view[write_channel_offset:write_channel_end])

        return (
            cls(
                offset=offset,
                file_id=file_id,
                channel=channel,
                remaining_bytes=remaining_bytes,
                flags=flags,
                data=data,
                write_channel_info=write_channel,
            ),
            48 + max(data_end, write_channel_end, 1),
        )


@dataclasses.dataclass(frozen=True)
class WriteResponse(SMBMessage):

    __slots__ = ("count", "remaining")

    count: int
    remaining: int

    def __init__(
        self,
        *,
        count: int,
        remaining: int,
    ) -> None:
        super().__init__(Command.WRITE)
        object.__setattr__(self, "count", count)
        object.__setattr__(self, "remaining", remaining)

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        return bytearray().join(
            [
                b"\x11\x00",  # StructureSize(17)
                b"\x00\x00",  # Reserved
                self.count.to_bytes(4, byteorder="little"),
                self.remaining.to_bytes(4, byteorder="little"),
                b"\x00\x00\x00\x00",  # WriteChannelInfoOffset/Length - not used
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["WriteResponse", int]:
        view = memoryview(data)[offset:]
        if len(view) < 16:
            raise MalformedPacket("Write response payload is too small")

        count = struct.unpack("<I", view[4:8])[0]
        remaining = struct.unpack("<I", view[8:12])[0]

        return (
            cls(
                count=count,
                remaining=remaining,
            ),
            16,
        )
