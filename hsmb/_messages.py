# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import enum
import struct
import typing
import uuid

from hsmb._negotiate_contexts import (
    NegotiateContext,
    pack_negotiate_context,
    unpack_negotiate_context,
)
from hsmb._tree_contexts import TreeContext, pack_tree_context, unpack_tree_context


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


class Dialect(enum.IntEnum):
    UNKNOWN = 0x0000
    SMB202 = 0x0202
    SMB210 = 0x0210
    SMB300 = 0x0300
    SMB302 = 0x0302
    SMB311 = 0x0311
    SMB2_WILDCARD = 0x02FF


class SecurityModes(enum.IntFlag):
    NONE = 0x0000
    SIGNING_ENABLED = 0x0001
    SIGNING_REQUIRED = 0x0002


class Capabilities(enum.IntFlag):
    NONE = 0x00000000
    DFS = 0x00000001
    LEASING = 0x00000002
    LARGE_MTU = 0x00000004
    MULTI_CHANNEL = 0x00000008
    PERSISTENT_HANDLES = 0x00000010
    DIRECTORY_LEASING = 0x00000020
    ENCRYPTION = 0x00000040


class SessionSetupFlags(enum.IntFlag):
    NONE = 0x0
    BINDING = 0x01


class SessionFlags(enum.IntFlag):
    IS_GUEST = 0x0001
    IS_NULL = 0x0002
    ENCRYPT_DATA = 0x0004


class TreeConnectFlags(enum.IntFlag):
    NONE = 0x0000
    CLUSTER_RECONNECT = 0x0001
    REDIRECT_TO_OWNER = 0x0002
    EXTENSION_PRESENT = 0x0004


class ShareType(enum.IntEnum):
    DISK = 0x01
    PIPE = 0x02
    PRINT = 0x03


class ShareFlags(enum.IntFlag):
    MANUAL_CACHING = 0x0000000
    DFS = 0x00000001
    DFS_ROOT = 0x00000002
    AUTO_CACHING = 0x00000010
    VDO_CACHING = 0x00000020
    NO_CACHING = 0x00000030
    RESTRICT_EXCLUSIVE_OPENS = 0x00000100
    FORCE_SHARED_DELETE = 0x00000200
    ALLOW_NAMESPACE_CACHING = 0x00000400
    ACCESS_BASED_DIRECTORY_ENUM = 0x00000400
    FORCE_LEVEL2_OPLOCK = 0x00001000
    ENABLE_HASH_V1 = 0x00002000
    ENABLE_HASH_V2 = 0x00004000
    ENCRYPT_DATA = 0x00008000
    IDENTITY_REMOTING = 0x00040000
    COMPRESS_DATA = 0x00100000


class ShareCapabilities(enum.IntFlag):
    DFS = 0x00000008
    CONTINUOUS_AVAILABILITY = 0x00000010
    SCALEOUT = 0x00000020
    CAP_CLUSTER = 0x00000040
    ASYMMETRIX = 0x00000080
    REDIRECT_TO_OWNER = 0x00000100


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
class SMB1NegotiateRequest(SMBMessage):
    __slots__ = ("dialects",)

    dialects: typing.List[str]

    def __init__(
        self,
        *,
        dialects: typing.List[str],
    ) -> None:
        super().__init__(Command.SMB1_NEGOTIATE)
        object.__setattr__(self, "dialects", dialects)

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        dialects = b"".join([b"\x02" + d.encode() + b"\x00" for d in self.dialects])

        return bytearray().join(
            [
                b"\x00",  # WordCount
                len(dialects).to_bytes(2, byteorder="little"),
                dialects,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["SMB1NegotiateRequest", int]:
        # FIXME
        dialects: typing.List[str] = []

        return SMB1NegotiateRequest(dialects=dialects), 0


@dataclasses.dataclass(frozen=True)
class SMB1NegotiateResponse(SMBMessage):
    __slots__ = ("selected_index",)

    selected_index: int

    def __init__(
        self,
        *,
        selected_index: int,
    ):
        super().__init__(Command.SMB1_NEGOTIATE)
        object.__setattr__(self, "selected_index", selected_index)

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        return bytearray().join(
            [
                b"\x01",  # WordCount
                self.selected_index.to_bytes(2, byteorder="little", signed=True),
                b"\x00\x00",  # ByteCount
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["SMB1NegotiateResponse", int]:
        view = memoryview(data)[offset:]

        selected_index = struct.unpack("<h", view[1:3])[0]
        return SMB1NegotiateResponse(selected_index=selected_index), 0


@dataclasses.dataclass(frozen=True)
class NegotiateRequest(SMBMessage):
    __slots__ = ("dialects", "security_mode", "capabilities", "client_guid", "negotiate_contexts")

    dialects: typing.List[Dialect]
    security_mode: SecurityModes
    capabilities: Capabilities
    client_guid: uuid.UUID
    negotiate_contexts: typing.List[NegotiateContext]

    def __init__(
        self,
        *,
        dialects: typing.List[Dialect],
        security_mode: SecurityModes,
        capabilities: Capabilities,
        client_guid: uuid.UUID,
        negotiate_contexts: typing.Optional[typing.List[NegotiateContext]] = None,
    ) -> None:
        super().__init__(Command.NEGOTIATE)
        object.__setattr__(self, "dialects", dialects)
        object.__setattr__(self, "security_mode", security_mode)
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "client_guid", client_guid)
        object.__setattr__(self, "negotiate_contexts", negotiate_contexts or [])

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        dialects = b"".join(d.to_bytes(2, byteorder="little") for d in self.dialects)
        negotiate_offset = 0
        padding_size = 0
        negotiate_contexts = []

        if self.negotiate_contexts:
            negotiate_offset = offset_from_header + 36 + len(dialects)
            padding_size = 8 - (negotiate_offset % 8 or 8)
            negotiate_offset += padding_size

            last_idx = len(self.negotiate_contexts) - 1
            for idx, context in enumerate(self.negotiate_contexts):
                context_data = pack_negotiate_context(context)
                negotiate_contexts.append(context_data)

                context_padding_size = 8 - (len(context_data) % 8 or 8)
                if idx != last_idx and context_padding_size:
                    negotiate_contexts.append(b"\x00" * context_padding_size)

        return bytearray().join(
            [
                b"\x24\x00",  # StructureSize(36)
                len(self.dialects).to_bytes(2, byteorder="little"),
                self.security_mode.value.to_bytes(2, byteorder="little"),
                b"\x00\x00",  # Reserved,
                self.capabilities.value.to_bytes(4, byteorder="little"),
                self.client_guid.bytes_le,
                negotiate_offset.to_bytes(4, byteorder="little"),
                len(self.negotiate_contexts).to_bytes(2, byteorder="little"),
                b"\x00\x00",  # Reserved2
                dialects,
                (b"\x00" * padding_size),
                b"".join(negotiate_contexts),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["NegotiateRequest", int]:
        view = memoryview(data)[offset:]

        dialect_count = struct.unpack("<H", view[2:4])[0]
        security_mode = SecurityModes(struct.unpack("<H", view[4:6])[0])
        capabilities = Capabilities(struct.unpack("<I", view[8:12])[0])
        client_guid = uuid.UUID(bytes_le=bytes(view[12:28]))
        context_offset = struct.unpack("<I", view[28:32])[0] - offset_from_header
        context_count = struct.unpack("<H", view[32:34])[0]

        end_idx = 36
        dialects: typing.List[Dialect] = []
        for _ in range(dialect_count):
            dialects.append(Dialect(struct.unpack("<H", view[end_idx : end_idx + 2])[0]))
            end_idx += 2

        contexts: typing.List[NegotiateContext] = []
        if context_count:
            end_idx = context_offset

            for idx in range(context_count):
                ctx, offset = unpack_negotiate_context(view[end_idx:])
                contexts.append(ctx)

                if idx != context_count - 1:
                    # Adjust for padding
                    offset += 8 - (offset % 8 or 8)

                end_idx += offset

        return (
            NegotiateRequest(
                dialects=dialects,
                security_mode=security_mode,
                capabilities=capabilities,
                client_guid=client_guid,
                negotiate_contexts=contexts,
            ),
            end_idx,
        )


@dataclasses.dataclass(frozen=True)
class NegotiateResponse(SMBMessage):
    __slots__ = (
        "security_mode",
        "dialect_revision",
        "server_guid",
        "capabilities",
        "max_transact_size",
        "max_read_size",
        "max_write_size",
        "system_time",
        "server_start_time",
        "security_buffer",
        "negotiate_contexts",
    )

    security_mode: SecurityModes
    dialect_revision: Dialect
    server_guid: uuid.UUID
    capabilities: Capabilities
    max_transact_size: int
    max_read_size: int
    max_write_size: int
    system_time: int
    server_start_time: int
    security_buffer: typing.Optional[bytes]
    negotiate_contexts: typing.List[NegotiateContext]

    def __init__(
        self,
        *,
        security_mode: SecurityModes,
        dialect_revision: Dialect,
        server_guid: uuid.UUID,
        capabilities: Capabilities,
        max_transact_size: int,
        max_read_size: int,
        max_write_size: int,
        system_time: int = 0,
        server_start_time: int = 0,
        security_buffer: typing.Optional[bytes] = None,
        negotiate_contexts: typing.Optional[typing.List[NegotiateContext]] = None,
    ) -> None:
        super().__init__(Command.NEGOTIATE)
        object.__setattr__(self, "security_mode", security_mode)
        object.__setattr__(self, "dialect_revision", dialect_revision)
        object.__setattr__(self, "server_guid", server_guid)
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "max_transact_size", max_transact_size)
        object.__setattr__(self, "max_read_size", max_read_size)
        object.__setattr__(self, "max_write_size", max_write_size)
        object.__setattr__(self, "system_time", system_time)
        object.__setattr__(self, "server_start_time", server_start_time)
        object.__setattr__(self, "security_buffer", security_buffer)
        object.__setattr__(self, "negotiate_contexts", negotiate_contexts or [])

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        sec_buffer = self.security_buffer or b""
        sec_buffer_offset = offset_from_header + 65
        negotiate_offset = 0
        padding_size = 0
        negotiate_contexts = []

        if self.negotiate_contexts:
            negotiate_offset = sec_buffer_offset + len(sec_buffer)
            padding_size = 8 - (negotiate_offset % 8 or 8)
            negotiate_offset += padding_size

            last_idx = len(self.negotiate_contexts) - 1
            for idx, context in enumerate(self.negotiate_contexts):
                context_data = pack_negotiate_context(context)
                negotiate_contexts.append(context_data)

                context_padding_size = 8 - (len(context_data) % 8 or 8)
                if idx != last_idx and context_padding_size:
                    negotiate_contexts.append(b"\x00" * context_padding_size)

        return bytearray().join(
            [
                b"\x41\x00",  # StructureSize(65)
                self.security_mode.value.to_bytes(2, byteorder="little"),
                self.dialect_revision.value.to_bytes(2, byteorder="little"),
                len(self.negotiate_contexts).to_bytes(2, byteorder="little"),
                self.server_guid.bytes_le,
                self.capabilities.value.to_bytes(4, byteorder="little"),
                self.max_transact_size.to_bytes(4, byteorder="little"),
                self.max_read_size.to_bytes(4, byteorder="little"),
                self.max_write_size.to_bytes(4, byteorder="little"),
                self.system_time.to_bytes(8, byteorder="little"),
                self.server_start_time.to_bytes(8, byteorder="little"),
                sec_buffer_offset.to_bytes(2, byteorder="little"),
                len(sec_buffer).to_bytes(2, byteorder="little"),
                negotiate_offset.to_bytes(4, byteorder="little"),
                sec_buffer,
                (b"\x00" * padding_size),
                b"".join(negotiate_contexts),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["NegotiateResponse", int]:
        view = memoryview(data)[offset:]

        security_mode = SecurityModes(struct.unpack("<H", view[2:4])[0])
        dialect_revision = Dialect(struct.unpack("<H", view[4:6])[0])
        context_count = struct.unpack("<H", view[6:8])[0]
        server_guid = uuid.UUID(bytes_le=bytes(view[8:24]))
        capabilities = Capabilities(struct.unpack("<I", view[24:28])[0])
        max_transact_size = struct.unpack("<I", view[28:32])[0]
        max_read_size = struct.unpack("<I", view[32:36])[0]
        max_write_size = struct.unpack("<I", view[36:40])[0]
        system_time = struct.unpack("<Q", view[40:48])[0]
        server_start_time = struct.unpack("<Q", view[48:56])[0]
        sec_buffer_offset = struct.unpack("<H", view[56:58])[0] - offset_from_header
        sec_buffer_length = struct.unpack("<H", view[58:60])[0]
        context_offset = struct.unpack("<I", view[60:64])[0] - offset_from_header

        end_idx = 64
        sec_buffer = None
        if sec_buffer_length:
            end_idx = sec_buffer_offset + sec_buffer_length
            sec_buffer = bytes(view[sec_buffer_offset:end_idx])

        contexts: typing.List[NegotiateContext] = []
        if context_count:
            end_idx = context_offset

            for idx in range(context_count):
                ctx, offset = unpack_negotiate_context(view[end_idx:])
                contexts.append(ctx)

                if idx != context_count - 1:
                    # Adjust for padding
                    offset += 8 - (offset % 8 or 8)

                end_idx += offset

        return (
            NegotiateResponse(
                security_mode=security_mode,
                dialect_revision=dialect_revision,
                server_guid=server_guid,
                capabilities=capabilities,
                max_transact_size=max_transact_size,
                max_read_size=max_read_size,
                max_write_size=max_write_size,
                system_time=system_time,
                server_start_time=server_start_time,
                security_buffer=sec_buffer,
                negotiate_contexts=contexts,
            ),
            end_idx,
        )


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
                self.flags.value.to_bytes(1, byteorder="little"),
                self.security_mode.value.to_bytes(1, byteorder="little"),
                self.capabilities.value.to_bytes(4, byteorder="little"),
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

        flags = SessionSetupFlags(struct.unpack("<B", view[2:3])[0])
        security_mode = SecurityModes(struct.unpack("<B", view[3:4])[0])
        capabilities = Capabilities(struct.unpack("<I", view[4:8])[0])
        channel = struct.unpack("<I", view[8:12])[0]
        sec_offset = struct.unpack("<H", view[12:14])[0] - offset_from_header
        sec_length = struct.unpack("<H", view[14:16])[0]
        previous_session_id = struct.unpack("<Q", view[16:24])[0]
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
                self.session_flags.value.to_bytes(2, byteorder="little"),
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

        session_flags = SessionFlags(struct.unpack("<H", view[2:4])[0])
        sec_offset = struct.unpack("<H", view[4:6])[0] - offset_from_header
        sec_length = struct.unpack("<H", view[6:8])[0]
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
            raise ValueError("Not enough data to unpack LogoffRequest")

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
            raise ValueError("Not enough data to unpack LogoffResponse")

        return LogoffResponse(), 4


@dataclasses.dataclass(frozen=True)
class TreeConnectRequest(SMBMessage):
    __slots__ = ("flags", "path", "tree_contexts")

    flags: TreeConnectFlags
    path: str
    tree_contexts: typing.List[TreeContext]

    def __init__(
        self,
        *,
        flags: TreeConnectFlags,
        path: str,
        tree_contexts: typing.List[TreeContext],
    ) -> None:
        super().__init__(Command.TREE_CONNECT)
        object.__setattr__(self, "flags", flags)
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "tree_contexts", tree_contexts)

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        b_path = self.path.encode("utf-16-le")

        path_offset = offset_from_header + 8
        extension_info = b""
        padding_size = 0
        tree_contexts = []

        if self.flags & TreeConnectFlags.EXTENSION_PRESENT:
            path_offset += 16
            extension_offset = 24 + len(b_path)
            padding_size = 8 - (extension_offset % 8 or 8)
            extension_offset += padding_size

            extension_info = b"".join(
                [
                    extension_offset.to_bytes(4, byteorder="little"),
                    len(self.tree_contexts).to_bytes(2, byteorder="little"),
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # Reserved
                ]
            )

            last_idx = len(self.tree_contexts) - 1
            for idx, context in enumerate(self.tree_contexts):
                context_data = pack_tree_context(context)
                tree_contexts.append(context_data)

                context_padding_size = 8 - (len(context_data) % 8 or 8)
                if idx != last_idx and context_padding_size:
                    tree_contexts.append(b"\x00" * context_padding_size)

        return bytearray().join(
            [
                b"\x09\x00",
                self.flags.value.to_bytes(2, byteorder="little"),
                path_offset.to_bytes(2, byteorder="little"),
                len(b_path).to_bytes(2, byteorder="little"),
                extension_info,
                b_path,
                (b"\x00" * padding_size),
                b"".join(tree_contexts),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["TreeConnectRequest", int]:
        view = memoryview(data)[offset:]

        flags = TreeConnectFlags(struct.unpack("<H", view[2:4])[0])
        path_offset = struct.unpack("<H", view[4:6])[0] - offset_from_header
        path_length = struct.unpack("<H", view[6:8])[0]
        path_name = bytes(view[path_offset : path_offset + path_length]).decode("utf-16-le")
        end_idx = path_offset + path_length

        contexts: typing.List[TreeContext] = []
        if flags & TreeConnectFlags.EXTENSION_PRESENT:
            context_offset = struct.unpack("<I", view[8:12])[0]
            context_count = struct.unpack("<H", view[12:14])[0]

            if context_count:
                end_idx = context_offset

                for idx in range(context_count):
                    ctx, offset = unpack_tree_context(view[end_idx:])
                    contexts.append(ctx)

                    if idx != context_count - 1:
                        # Adjust for padding
                        offset += 8 - (offset % 8 or 8)

                    end_idx += offset

        return (
            TreeConnectRequest(
                flags=flags,
                path=path_name,
                tree_contexts=contexts,
            ),
            end_idx,
        )


@dataclasses.dataclass(frozen=True)
class TreeConnectResponse(SMBMessage):
    __slots__ = ("share_type", "share_flags", "capabilities", "maximal_access")

    share_type: ShareType
    share_flags: ShareFlags
    capabilities: ShareCapabilities
    maximal_access: int

    def __init__(
        self,
        *,
        share_type: ShareType,
        share_flags: ShareFlags,
        capabilities: ShareCapabilities,
        maximal_access: int,
    ) -> None:
        super().__init__(Command.TREE_CONNECT)
        object.__setattr__(self, "share_type", share_type)
        object.__setattr__(self, "share_flags", share_flags)
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "maximal_access", maximal_access)

    def pack(
        self,
        offset_from_header: int,
    ) -> bytearray:
        return bytearray().join(
            [
                b"\x10\x00",
                self.share_type.value.to_bytes(1, byteorder="little"),
                b"\x00",  # Reserved
                self.share_flags.value.to_bytes(4, byteorder="little"),
                self.capabilities.value.to_bytes(4, byteorder="little"),
                self.maximal_access.to_bytes(4, byteorder="little"),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset_from_header: int,
        offset: int = 0,
    ) -> typing.Tuple["TreeConnectResponse", int]:
        view = memoryview(data)[offset:]

        share_type = ShareType(struct.unpack("<B", view[2:3])[0])
        share_flags = ShareFlags(struct.unpack("<I", view[4:8])[0])
        capabilities = ShareCapabilities(struct.unpack("<I", view[8:12])[0])
        maximal_access = struct.unpack("<I", view[12:16])[0]

        return (
            TreeConnectResponse(
                share_type=share_type,
                share_flags=share_flags,
                capabilities=capabilities,
                maximal_access=maximal_access,
            ),
            16,
        )


@dataclasses.dataclass(frozen=True)
class TreeDisconnectRequest(SMBMessage):
    __slots__ = ()

    def __init__(
        self,
    ) -> None:
        super().__init__(Command.TREE_DISCONNECT)

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
    ) -> typing.Tuple["TreeDisconnectRequest", int]:
        view = memoryview(data)[offset:]
        if len(view) < 4:
            raise ValueError("Not enough data to unpack TreeDisconnectRequest")

        return TreeDisconnectRequest(), 4


@dataclasses.dataclass(frozen=True)
class TreeDisconnectResponse(SMBMessage):
    __slots__ = ()

    def __init__(
        self,
    ) -> None:
        super().__init__(Command.TREE_DISCONNECT)

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
    ) -> typing.Tuple["TreeDisconnectResponse", int]:
        view = memoryview(data)[offset:]
        if len(view) < 4:
            raise ValueError("Not enough data to unpack TreeDisconnectResponse")

        return TreeDisconnectResponse(), 4


MESSAGES: typing.Dict[Command, typing.Tuple[typing.Type[SMBMessage], typing.Type[SMBMessage]]] = {
    Command.SMB1_NEGOTIATE: (SMB1NegotiateRequest, SMB1NegotiateResponse),
    Command.NEGOTIATE: (NegotiateRequest, NegotiateResponse),
    Command.SESSION_SETUP: (SessionSetupRequest, SessionSetupResponse),
    Command.LOGOFF: (LogoffRequest, LogoffResponse),
    Command.TREE_CONNECT: (TreeConnectRequest, TreeConnectResponse),
    Command.TREE_DISCONNECT: (TreeDisconnectRequest, TreeDisconnectResponse),
}
