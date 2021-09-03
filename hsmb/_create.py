# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import enum
import struct
import typing

from hsmb._exceptions import MalformedPacket
from hsmb._messages import Command, SMBMessage


class RequestedOplockLevel(enum.IntEnum):
    NONE = 0x00
    II = 0x01
    EXCLUSIVE = 0x08
    BATCH = 0x09
    LEASE = 0xFF


class ImpersonationLevel(enum.IntEnum):
    ANONYMOUS = 0x00000000
    IDENTIFICATION = 0x00000001
    IMPERSONATION = 0x00000002
    DELEGATE = 0x00000003


class ShareAccess(enum.IntFlag):
    NONE = 0x00000000
    READ = 0x00000001
    WRITE = 0x00000002
    DELETE = 0x00000004


class CreateDisposition(enum.IntEnum):
    SUPERSEDE = 0x00000000
    OPEN = 0x00000001
    CREATE = 0x00000002
    OPEN_IF = 0x00000003
    OVERWRITE = 0x00000004
    OVERWRITE_IF = 0x00000005


class CreateOptions(enum.IntFlag):
    NONE = 0x00000000
    DIRECTORY_FILE = 0x00000001
    WRITE_THROUGH = 0x00000002
    SEQUENTIAL_ONLY = 0x00000004
    NO_INTERMEDIATE_BUFFERING = 0x00000008
    SYNCHRONOUS_IO_ALERT = 0x00000010
    SYNCHRONOUS_IO_NONALERT = 0x00000020
    NON_DIRECTORY_FILE = 0x00000040
    COMPLETE_IF_OPLOCKED = 0x00000100
    NO_EA_KNOWLEDGE = 0x00000200
    OPEN_REMOTE_INSTANCE = 0x00000400
    RANDOM_ACCESS = 0x00000800
    DELETE_ON_CLOSE = 0x00001000
    OPEN_BY_FILE_ID = 0x00002000
    OPEN_FOR_BACKUP_INTENT = 0x00004000
    NO_COMPRESSION = 0x00008000
    OPEN_REQUIRING_OPLOCK = 0x00010000
    DISALLOW_EXCLUSIVE = 0x00020000
    RESERVE_OPFILTER = 0x00100000
    OPEN_REPARSE_POINT = 0x00200000
    OPEN_NO_RECALL = 0x00400000
    OPEN_FOR_FREE_SPACE_QUERY = 0x00800000


class CreateResponseFlags(enum.IntFlag):
    NONE = 0x00
    REPARSEPOINT = 0x01


class CreateAction(enum.IntEnum):
    SUPERSEDED = 0x00000000
    OPENED = 0x00000001
    CREATED = 0x00000002
    OVERWRITTEN = 0x00000003


class CloseFlags(enum.IntFlag):
    NONE = 0x0000
    POSTQUERY_ATTRIB = 0x0001


@dataclasses.dataclass(frozen=True)
class CreateRequest(SMBMessage):
    __slots__ = (
        "requested_oplock_level",
        "impersonation_level",
        "desired_access",
        "file_attributes",
        "share_access",
        "create_disposition",
        "create_options",
        "name",
        "create_contexts",
        "security_flags",
        "smb_create_flags",
    )

    requested_oplock_level: RequestedOplockLevel
    impersonation_level: ImpersonationLevel
    desired_access: int
    file_attributes: int
    share_access: ShareAccess
    create_disposition: CreateDisposition
    create_options: CreateOptions
    name: str
    create_contexts: typing.List
    security_flags: int
    smb_create_flags: int

    def __init__(
        self,
        *,
        requested_oplock_level: RequestedOplockLevel,
        impersonation_level: ImpersonationLevel,
        desired_access: int,
        file_attributes: int,
        share_access: ShareAccess,
        create_disposition: CreateDisposition,
        create_options: CreateOptions,
        name: str,
        create_contexts: typing.Optional[typing.List] = None,
        security_flags: int = 0,
        smb_create_flags: int = 0,
    ) -> None:
        super().__init__(Command.CREATE)
        object.__setattr__(self, "requested_oplock_level", requested_oplock_level)
        object.__setattr__(self, "impersonation_level", impersonation_level)
        object.__setattr__(self, "desired_access", desired_access)
        object.__setattr__(self, "file_attributes", file_attributes)
        object.__setattr__(self, "share_access", share_access)
        object.__setattr__(self, "create_disposition", create_disposition)
        object.__setattr__(self, "create_options", create_options)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "create_contexts", create_contexts or [])
        object.__setattr__(self, "security_flags", security_flags)
        object.__setattr__(self, "smb_create_flags", smb_create_flags)

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        buffer = bytearray(self.name.encode("utf-16-le"))
        name_offset = offset_from_header + 56
        name_length = len(buffer)

        create_contexts_offset = 0
        create_contexts_length = 0
        if self.create_contexts:
            create_contexts_offset = name_offset + name_length
            padding_size = 8 - (create_contexts_offset % 8 or 8)
            create_contexts_offset += padding_size
            buffer += b"\x00" * padding_size

            last_idx = len(self.create_contexts) - 1
            for idx, context in enumerate(self.create_contexts):
                context_data = bytearray()  # FIXME
                buffer += context_data

                context_padding_size = 8 - (len(context_data) % 8 or 8)
                if idx != last_idx and context_padding_size:
                    buffer += b"\x00" * context_padding_size

        return bytearray().join(
            [
                b"\x39\x00",  # StructureSize(57)
                self.security_flags.to_bytes(1, byteorder="little"),
                self.requested_oplock_level.to_bytes(1, byteorder="little"),
                self.impersonation_level.to_bytes(4, byteorder="little"),
                self.smb_create_flags.to_bytes(8, byteorder="little"),
                b"\x00\x00\x00\x00\x00\x00\x00\x00",  # Reserved
                self.desired_access.to_bytes(4, byteorder="little"),
                self.file_attributes.to_bytes(4, byteorder="little"),
                self.share_access.to_bytes(4, byteorder="little"),
                self.create_disposition.to_bytes(4, byteorder="little"),
                self.create_options.to_bytes(4, byteorder="little"),
                name_offset.to_bytes(2, byteorder="little"),
                name_length.to_bytes(2, byteorder="little"),
                create_contexts_offset.to_bytes(4, byteorder="little"),
                create_contexts_length.to_bytes(4, byteorder="little"),
                buffer or b"\x00",  # Must contain at least 1 byte
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["CreateRequest", int]:
        view = memoryview(data)[offset:]

        if len(view) < 57:
            raise MalformedPacket("Create request payload is too small")

        security_flags = struct.unpack("<B", view[2:3])[0]
        requested_oplock_level = RequestedOplockLevel(struct.unpack("<B", view[3:4])[0])
        impersonation_level = ImpersonationLevel(struct.unpack("<I", view[4:8])[0])
        smb_create_flags = struct.unpack("<Q", view[8:16])[0]
        desired_access = struct.unpack("<I", view[24:28])[0]
        file_attributes = struct.unpack("<I", view[28:32])[0]
        share_access = ShareAccess(struct.unpack("<I", view[32:36])[0])
        create_disposition = CreateDisposition(struct.unpack("<I", view[36:40])[0])
        create_options = CreateOptions(struct.unpack("<I", view[40:44])[0])
        name_offset = struct.unpack("<H", view[44:46])[0] - offset_from_header
        name_length = struct.unpack("<H", view[46:48])[0]
        contexts_offset = struct.unpack("<I", view[48:52])[0] - offset_from_header
        contexts_length = struct.unpack("<I", view[52:56])[0]

        name = ""
        name_end = 0
        if name_length:
            name_end = name_offset + name_length
            if len(view) < name_end:
                raise MalformedPacket("Create request name buffer is out of bounds")

            name = bytes(view[name_offset:name_end]).decode("utf-16-le")

        contexts: typing.List = []
        contexts_end = 0
        if contexts_length:
            contexts_end = contexts_offset + contexts_length
            if len(view) < contexts_end:
                raise MalformedPacket("Create request create contexts buffer is out of bounds")
            # FIXME: unpack contexts

        return (
            cls(
                requested_oplock_level=requested_oplock_level,
                impersonation_level=impersonation_level,
                desired_access=desired_access,
                file_attributes=file_attributes,
                share_access=share_access,
                create_disposition=create_disposition,
                create_options=create_options,
                name=name,
                create_contexts=contexts,
                security_flags=security_flags,
                smb_create_flags=smb_create_flags,
            ),
            56 + max(name_end, contexts_end, 1),
        )


@dataclasses.dataclass(frozen=True)
class CreateResponse(SMBMessage):
    __slots__ = (
        "oplock_level",
        "flags",
        "create_action",
        "creation_time",
        "last_access_time",
        "last_write_time",
        "change_time",
        "allocation_size",
        "end_of_file",
        "file_attributes",
        "file_id",
        "create_contexts",
    )

    oplock_level: RequestedOplockLevel
    flags: CreateResponseFlags
    create_action: CreateAction
    creation_time: int
    last_access_time: int
    last_write_time: int
    change_time: int
    allocation_size: int
    end_of_file: int
    file_attributes: int
    file_id: bytes
    create_contexts: typing.List

    def __init__(
        self,
        *,
        oplock_level: RequestedOplockLevel,
        flags: CreateResponseFlags,
        create_action: CreateAction,
        creation_time: int,
        last_access_time: int,
        last_write_time: int,
        change_time: int,
        allocation_size: int,
        end_of_file: int,
        file_attributes: int,
        file_id: bytes,
        create_contexts: typing.Optional[typing.List] = None,
    ) -> None:
        super().__init__(Command.CREATE)
        object.__setattr__(self, "oplock_level", oplock_level)
        object.__setattr__(self, "flags", flags)
        object.__setattr__(self, "create_action", create_action)
        object.__setattr__(self, "creation_time", creation_time)
        object.__setattr__(self, "last_access_time", last_access_time)
        object.__setattr__(self, "last_write_time", last_write_time)
        object.__setattr__(self, "change_time", change_time)
        object.__setattr__(self, "allocation_size", allocation_size)
        object.__setattr__(self, "end_of_file", end_of_file)
        object.__setattr__(self, "file_attributes", file_attributes)
        object.__setattr__(self, "file_id", file_id)
        object.__setattr__(self, "create_contexts", create_contexts or [])

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        context_offset = 0
        context_length = 0
        buffer = bytearray()

        if self.create_contexts:
            contexts_offset = 88 + offset_from_header
            padding_size = 8 - (contexts_offset % 8 or 8)
            contexts_offset += padding_size
            buffer += b"\x00" * padding_size

            last_idx = len(self.create_contexts) - 1
            for idx, context in enumerate(self.create_contexts):
                context_data = bytearray()  # FIXME
                buffer += context_data

                context_padding_size = 8 - (len(context_data) % 8 or 8)
                if idx != last_idx and context_padding_size:
                    buffer += b"\x00" * context_padding_size

        return bytearray().join(
            [
                b"\x59\x00",  # StructureSize(89)
                self.oplock_level.to_bytes(1, byteorder="little"),
                self.flags.to_bytes(1, byteorder="little"),
                self.create_action.to_bytes(4, byteorder="little"),
                self.creation_time.to_bytes(8, byteorder="little"),
                self.last_access_time.to_bytes(8, byteorder="little"),
                self.last_write_time.to_bytes(8, byteorder="little"),
                self.change_time.to_bytes(8, byteorder="little"),
                self.allocation_size.to_bytes(8, byteorder="little"),
                self.end_of_file.to_bytes(8, byteorder="little"),
                self.file_attributes.to_bytes(4, byteorder="little"),
                b"\x00\x00\x00\x00",  # Reserved2
                self.file_id,
                context_offset.to_bytes(4, byteorder="little"),
                context_length.to_bytes(4, byteorder="little"),
                buffer,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["CreateResponse", int]:
        view = memoryview(data)[offset:]

        if len(view) < 88:
            raise MalformedPacket("Create response payload is too small")

        oplock_level = RequestedOplockLevel(struct.unpack("<B", view[2:3])[0])
        flags = CreateResponseFlags(struct.unpack("<B", view[3:4])[0])
        create_action = CreateAction(struct.unpack("<I", view[4:8])[0])
        creation_time = struct.unpack("<Q", view[8:16])[0]
        last_access_time = struct.unpack("<Q", view[16:24])[0]
        last_write_time = struct.unpack("<Q", view[24:32])[0]
        change_time = struct.unpack("<Q", view[32:40])[0]
        allocation_size = struct.unpack("<Q", view[40:48])[0]
        end_of_file = struct.unpack("<Q", view[48:56])[0]
        file_attributes = struct.unpack("<I", view[56:60])[0]
        file_id = bytes(view[64:80])
        contexts_offset = struct.unpack("<I", view[80:84])[0] - offset_from_header
        contexts_length = struct.unpack("<I", view[84:88])[0]

        end_idx = 88  # FIXME: should this be 89 is there a end byte if no contexts
        contexts: typing.List = []
        if contexts_length:
            end_idx = contexts_offset + contexts_length
            if len(view) < end_idx:
                raise MalformedPacket("Create response create contexts buffer is out of bounds")
            # FIXME: unpack contexts

        return (
            cls(
                oplock_level=oplock_level,
                flags=flags,
                create_action=create_action,
                creation_time=creation_time,
                last_access_time=last_access_time,
                last_write_time=last_write_time,
                change_time=change_time,
                allocation_size=allocation_size,
                end_of_file=end_of_file,
                file_attributes=file_attributes,
                file_id=file_id,
                create_contexts=contexts,
            ),
            end_idx,
        )


@dataclasses.dataclass(frozen=True)
class CloseRequest(SMBMessage):
    __slots__ = ("flags", "file_id")

    flags: CloseFlags
    file_id: bytes

    def __init__(
        self,
        *,
        flags: CloseFlags,
        file_id: bytes,
    ) -> None:
        super().__init__(Command.CLOSE)
        object.__setattr__(self, "flags", flags)
        object.__setattr__(self, "file_id", file_id)

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        return bytearray().join(
            [
                b"\x18\x00",  # StructureSize(24)
                self.flags.to_bytes(2, byteorder="little"),
                b"\x00\x00\x00\x00",  # Reserved
                self.file_id,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["CloseRequest", int]:
        view = memoryview(data)[offset:]

        if len(view) < 24:
            raise MalformedPacket("Close request payload is too small")

        flags = CloseFlags(struct.unpack("<H", view[2:4])[0])
        file_id = bytes(view[8:24])

        return cls(flags=flags, file_id=file_id), 24


@dataclasses.dataclass(frozen=True)
class CloseResponse(SMBMessage):
    __slots__ = (
        "flags",
        "creation_time",
        "last_access_time",
        "last_write_time",
        "change_time",
        "allocation_size",
        "end_of_file",
        "file_attributes",
    )

    flags: CloseFlags
    creation_time: int
    last_access_time: int
    last_write_time: int
    change_time: int
    allocation_size: int
    end_of_file: int
    file_attributes: int

    def __init__(
        self,
        *,
        flags: CloseFlags,
        creation_time: int,
        last_access_time: int,
        last_write_time: int,
        change_time: int,
        allocation_size: int,
        end_of_file: int,
        file_attributes: int,
    ) -> None:
        super().__init__(Command.CLOSE)
        object.__setattr__(self, "flags", flags)
        object.__setattr__(self, "creation_time", creation_time)
        object.__setattr__(self, "last_access_time", last_access_time)
        object.__setattr__(self, "last_write_time", last_write_time)
        object.__setattr__(self, "change_time", change_time)
        object.__setattr__(self, "allocation_size", allocation_size)
        object.__setattr__(self, "end_of_file", end_of_file)
        object.__setattr__(self, "file_attributes", file_attributes)

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        return bytearray().join(
            [
                b"\x3C\x00",  # StructureSize(60)
                self.flags.to_bytes(2, byteorder="little"),
                b"\x00\x00\x00\x00",  # Reserved
                self.creation_time.to_bytes(8, byteorder="little"),
                self.last_access_time.to_bytes(8, byteorder="little"),
                self.last_write_time.to_bytes(8, byteorder="little"),
                self.change_time.to_bytes(8, byteorder="little"),
                self.allocation_size.to_bytes(8, byteorder="little"),
                self.end_of_file.to_bytes(8, byteorder="little"),
                self.file_attributes.to_bytes(4, byteorder="little"),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["CloseResponse", int]:
        view = memoryview(data)[offset:]

        if len(view) < 60:
            raise MalformedPacket("Close response payload is too small")

        flags = CloseFlags(struct.unpack("<H", view[2:4])[0])
        creation_time = struct.unpack("<Q", view[8:16])[0]
        last_access_time = struct.unpack("<Q", view[16:24])[0]
        last_write_time = struct.unpack("<Q", view[24:32])[0]
        change_time = struct.unpack("<Q", view[32:40])[0]
        allocation_size = struct.unpack("<Q", view[40:48])[0]
        end_of_file = struct.unpack("<Q", view[48:56])[0]
        file_attributes = struct.unpack("<I", view[56:60])[0]
        return (
            cls(
                flags=flags,
                creation_time=creation_time,
                last_access_time=last_access_time,
                last_write_time=last_write_time,
                change_time=change_time,
                allocation_size=allocation_size,
                end_of_file=end_of_file,
                file_attributes=file_attributes,
            ),
            60,
        )
