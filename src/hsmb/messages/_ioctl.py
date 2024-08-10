# Copyright: (c) 2024, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import enum
import struct
import uuid

from hsmb._exceptions import MalformedPacket
from hsmb.messages._messages import Command, SMBMessage
from hsmb.messages._negotiate import Capabilities, Dialect, SecurityModes


class CtlCode(enum.IntEnum):
    DFS_GET_REFERRALS = 0x00060194
    PIPE_PEEK = 0x0011400C
    PIPE_WAIT = 0x00110018
    PIPE_TRANSCEIVE = 0x0011C017
    SRV_COPYCHUNK = 0x001440F2
    SRC_ENUMERATE_SNAPSHOTS = 0x00144064
    SRV_REQUEST_RESUME_KEY = 0x00140078
    SRV_READ_HASH = 0x001441BB
    SRV_COPYCHUNK_WRITE = 0x001480F2
    LMR_REQUEST_RESILIENCY = 0x001401D4
    QUERY_NETWORK_INTERFACE_INFO = 0x001401FC
    SET_REPARSE_POINT = 0x000900A4
    DFS_GET_REFERRALS_EX = 0x000601B0
    FILE_LEVEL_TRIM = 0x00098208
    VALIDATE_NEGOTIATE_INFO = 0x00140204


class IOCTLFlags(enum.IntEnum):
    NONE = 0x00000000
    IS_FSCTL = 0x00000001


@dataclasses.dataclass(frozen=True)
class ValidateNegotiateInfoRequest:

    __slots__ = ("capabilities", "guid", "security_mode", "dialects")

    capabilities: Capabilities
    guid: uuid.UUID
    security_mode: SecurityModes
    dialects: list[Dialect]

    ctl_code: CtlCode = CtlCode.VALIDATE_NEGOTIATE_INFO
    file_id: bytes = b"\xFF" * 16
    flags = IOCTLFlags = IOCTLFlags.IS_FSCTL
    max_output_response: int = 24

    def __init__(
        self,
        *,
        capabilities: Capabilities,
        guid: uuid.UUID,
        security_mode: SecurityModes,
        dialects: list[Dialect],
    ) -> None:
        super().__init__()
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "guid", guid)
        object.__setattr__(self, "security_mode", security_mode)
        object.__setattr__(self, "dialects", dialects)

    def pack(
        self,
    ) -> bytearray:
        return bytearray().join(
            [
                self.capabilities.to_bytes(4, byteorder="little"),
                self.guid.bytes_le,
                self.security_mode.to_bytes(2, byteorder="little"),
                len(self.dialects).to_bytes(2, byteorder="little"),
                b"".join([d.to_bytes(2, byteorder="little") for d in self.dialects]),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: bytes | bytearray | memoryview,
        offset: int = 0,
    ) -> ValidateNegotiateInfoRequest:
        view = memoryview(data)[offset:]

        if len(view) < 24:
            raise MalformedPacket(f"Not enough data to unpack {cls.__name__}")

        capabilities = Capabilities(struct.unpack("<I", view[0:4])[0])
        guid = uuid.UUID(bytes_le=bytes(view[4:20]))
        security_mode = SecurityModes(struct.unpack("<H", view[20:22])[0])
        dialect_count = struct.unpack("<H", view[22:24])[0]

        if len(view) < (24 + (dialect_count * 2)):
            raise MalformedPacket(f"{cls.__name__} dialect buffer is out of bounds")

        end_idx = 24
        dialects: list[Dialect] = []
        for _ in range(dialect_count):
            dialects.append(
                Dialect(struct.unpack("<H", view[end_idx : end_idx + 2])[0])
            )
            end_idx += 2

        return ValidateNegotiateInfoRequest(
            capabilities=capabilities,
            guid=guid,
            security_mode=security_mode,
            dialects=dialects,
        )


@dataclasses.dataclass(frozen=True)
class ValidateNegotiateInfoResponse:

    __slots__ = ("capabilities", "guid", "security_mode", "dialect")

    capabilities: Capabilities
    guid: uuid.UUID
    security_mode: SecurityModes
    dialect: Dialect

    ctl_code: CtlCode = CtlCode.VALIDATE_NEGOTIATE_INFO
    file_id: bytes = b"\xFF" * 16
    flags = IOCTLFlags = IOCTLFlags.IS_FSCTL

    def __init__(
        self,
        *,
        capabilities: Capabilities,
        guid: uuid.UUID,
        security_mode: SecurityModes,
        dialect: Dialect,
    ) -> None:
        super().__init__()
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "guid", guid)
        object.__setattr__(self, "security_mode", security_mode)
        object.__setattr__(self, "dialect", dialect)

    def pack(
        self,
    ) -> bytearray:
        return bytearray().join(
            [
                self.capabilities.to_bytes(4, byteorder="little"),
                self.guid.bytes_le,
                self.security_mode.to_bytes(2, byteorder="little"),
                self.dialect.to_bytes(2, byteorder="little"),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: bytes | bytearray | memoryview,
        offset: int = 0,
    ) -> ValidateNegotiateInfoResponse:
        view = memoryview(data)[offset:]

        if len(view) < 24:
            raise MalformedPacket(f"Not enough data to unpack {cls.__name__}")

        capabilities = Capabilities(struct.unpack("<I", view[0:4])[0])
        guid = uuid.UUID(bytes_le=bytes(view[4:20]))
        security_mode = SecurityModes(struct.unpack("<H", view[20:22])[0])
        dialect = Dialect(struct.unpack("<H", view[22:24])[0])

        return ValidateNegotiateInfoResponse(
            capabilities=capabilities,
            guid=guid,
            security_mode=security_mode,
            dialect=dialect,
        )


@dataclasses.dataclass(frozen=True)
class IOCTLRequest(SMBMessage):
    __slots__ = (
        "ctl_code",
        "file_id",
        "flags",
        "max_input_response",
        "max_output_response",
        "input",
        "output",
    )

    ctl_code: int
    file_id: bytes
    max_input_response: int
    max_output_response: int
    flags: IOCTLFlags
    input: bytes
    output: bytes

    def __init__(
        self,
        *,
        ctl_code: int,
        file_id: bytes,
        flags: IOCTLFlags,
        max_input_response: int = 0,
        max_output_response: int = 0,
        input: bytes = b"",
        output: bytes = b"",
    ) -> None:
        super().__init__(Command.IOCTL)
        object.__setattr__(self, "ctl_code", ctl_code)
        object.__setattr__(self, "file_id", file_id)
        object.__setattr__(self, "flags", flags)
        object.__setattr__(self, "max_input_response", max_input_response)
        object.__setattr__(self, "max_output_response", max_output_response)
        object.__setattr__(self, "input", input)
        object.__setattr__(self, "output", output)

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        buffer_offset = offset_from_header + 56

        input_offset = 0
        input_count = len(self.input)
        if input_count:
            input_offset = buffer_offset
            buffer_offset += input_count

        output_offset = 0
        output_count = len(self.output)
        if output_count:
            output_offset = buffer_offset

        return bytearray().join(
            [
                b"\x39\x00",  # StructureSize(57),
                b"\x00\x00",  # Reserved
                self.ctl_code.to_bytes(4, byteorder="little"),
                self.file_id,
                input_offset.to_bytes(4, byteorder="little"),
                input_count.to_bytes(4, byteorder="little"),
                self.max_input_response.to_bytes(4, byteorder="little"),
                output_offset.to_bytes(4, byteorder="little"),
                output_count.to_bytes(4, byteorder="little"),
                self.max_output_response.to_bytes(4, byteorder="little"),
                self.flags.to_bytes(4, byteorder="little"),
                b"\x00\x00\x00\x00",  # Reserved2
                self.input,
                self.output,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: bytes | bytearray | memoryview,
        offset_from_header: int,
        offset: int = 0,
    ) -> IOCTLRequest:
        view = memoryview(data)[offset:]

        if len(view) < 56:
            raise MalformedPacket(f"Not enough data to unpack {cls.__name__}")

        ctl_code = struct.unpack("<I", view[4:8])[0]
        file_id = bytes(view[8:24])
        input_offset = struct.unpack("<I", view[24:28])[0] - offset_from_header
        input_count = struct.unpack("<I", view[28:32])[0]
        max_input_response = struct.unpack("<I", view[32:36])[0]
        output_offset = struct.unpack("<I", view[36:40])[0] - offset_from_header
        output_count = struct.unpack("<I", view[40:44])[0]
        max_output_response = struct.unpack("<I", view[44:48])[0]
        flags = IOCTLFlags(struct.unpack("<I", view[48:52])[0])

        input = b""
        input_end = 0
        if input_count:
            if len(view) < (input_offset + input_count):
                raise MalformedPacket(f"{cls.__name__} input buffer is out of bounds")

            input_end = input_offset + input_count
            input = bytes(view[input_offset:input_end])

        output = b""
        output_end = 0
        if output_count:
            if len(view) < (output_offset + output_count):
                raise MalformedPacket(f"{cls.__name__} output buffer is out of bounds")

            output_end = output_offset + output_count
            output = bytes(view[output_offset:output_end])

        return IOCTLRequest(
            ctl_code=ctl_code,
            file_id=file_id,
            flags=flags,
            max_input_response=max_input_response,
            max_output_response=max_output_response,
            input=input,
            output=output,
        )


@dataclasses.dataclass(frozen=True)
class IOCTLResponse(SMBMessage):
    __slots__ = ("ctl_code", "file_id", "flags", "input", "output")

    ctl_code: int
    file_id: bytes
    flags: int
    input: bytes
    output: bytes

    def __init__(
        self,
        *,
        ctl_code: int,
        file_id: bytes,
        flags: int = 0,
        input: bytes = b"",
        output: bytes = b"",
    ) -> None:
        super().__init__(Command.IOCTL)
        object.__setattr__(self, "ctl_code", ctl_code)
        object.__setattr__(self, "file_id", file_id)
        object.__setattr__(self, "flags", flags)
        object.__setattr__(self, "input", input)
        object.__setattr__(self, "output", output)

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        buffer_offset = offset_from_header + 56

        input_offset = 0
        input_count = len(self.input)
        if input_count:
            input_offset = buffer_offset
            buffer_offset += input_count

        output_offset = 0
        output_count = len(self.output)
        if output_count:
            output_offset = buffer_offset

        return bytearray().join(
            [
                b"\x31\x00",  # StructureSize(49),
                b"\x00\x00",  # Reserved
                self.ctl_code.to_bytes(4, byteorder="little"),
                self.file_id,
                input_offset.to_bytes(4, byteorder="little"),
                input_count.to_bytes(4, byteorder="little"),
                output_offset.to_bytes(4, byteorder="little"),
                output_count.to_bytes(4, byteorder="little"),
                self.flags.to_bytes(4, byteorder="little"),
                b"\x00\x00\x00\x00",  # Reserved2
                self.input,
                self.output,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: bytes | bytearray | memoryview,
        offset_from_header: int,
        offset: int = 0,
    ) -> IOCTLResponse:
        view = memoryview(data)[offset:]

        if len(view) < 48:
            raise MalformedPacket(f"Not enough data to unpack {cls.__name__}")

        ctl_code = struct.unpack("<I", view[4:8])[0]
        file_id = bytes(view[8:24])
        input_offset = struct.unpack("<I", view[24:28])[0] - offset_from_header
        input_count = struct.unpack("<I", view[28:32])[0]
        output_offset = struct.unpack("<I", view[32:36])[0] - offset_from_header
        output_count = struct.unpack("<I", view[36:40])[0]
        flags = IOCTLFlags(struct.unpack("<I", view[40:44])[0])

        input = b""
        input_end = 0
        if input_count:
            if len(view) < (input_offset + input_count):
                raise MalformedPacket(f"{cls.__name__} input buffer is out of bounds")

            input_end = input_offset + input_count
            input = bytes(view[input_offset:input_end])

        output = b""
        output_end = 0
        if output_count:
            if len(view) < (output_offset + output_count):
                raise MalformedPacket(f"{cls.__name__} output buffer is out of bounds")

            output_end = output_offset + output_count
            output = bytes(view[output_offset:output_end])

        return IOCTLResponse(
            ctl_code=ctl_code,
            file_id=file_id,
            flags=flags,
            input=input,
            output=output,
        )
