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
    CAP_ENCRYPTION = 0x00000040


class SessionSetupFlags(enum.IntFlag):
    BINDING = 0x01


class SessionFlags(enum.IntFlag):
    IS_GUEST = 0x0001
    IS_NULL = 0x0002
    ENCRYPT_DATA = 0x0004


class TreeConnectFlags(enum.IntFlag):
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

    def pack(self) -> bytes:
        raise NotImplementedError()

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset: int = 0,
    ) -> "SMBMessage":
        raise NotImplementedError()


@dataclasses.dataclass(frozen=True)
class SMB1NegotiateRequest:
    __slots__ = ("dialects",)

    dialects: typing.List[str]

    def __init__(
        self,
        *,
        dialects: typing.List[str],
    ) -> None:
        object.__setattr__(self, "dialects", dialects)

    def pack(self) -> bytes:
        dialects = b"".join([b"\x02" + d.encode() + b"\x00" for d in self.dialects])

        return b"".join(
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
        offset: int = 0,
    ) -> "SMB1NegotiateRequest":
        dialects: typing.List[str] = []

        return SMB1NegotiateRequest(dialects=dialects)


@dataclasses.dataclass(frozen=True)
class SMB1NegotiateResponse:
    __slots__ = ("selected_index",)

    selected_index: int

    def __init__(
        self,
        *,
        selected_index: int,
    ):
        object.__setattr__(self, "selected_index", selected_index)

    def pack(self) -> bytes:
        return b"".join(
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
        offset: int = 0,
    ) -> "SMB1NegotiateResponse":
        view = memoryview(data)[offset:]

        selected_index = struct.unpack("<h", view[1:3])[0]
        return SMB1NegotiateResponse(selected_index=selected_index)


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

    def pack(self) -> bytes:
        dialects = b"".join(d.to_bytes(2, byteorder="little") for d in self.dialects)
        negotiate_offset = 0
        padding_size = 0
        negotiate_contexts = []

        if self.negotiate_contexts:
            # 100 == header + negotiate structure size
            negotiate_offset = 100 + len(dialects)
            padding_size = 8 - (negotiate_offset % 8 or 8)
            negotiate_offset += padding_size

            last_idx = len(self.negotiate_contexts) - 1
            for idx, context in enumerate(self.negotiate_contexts):
                negotiate_contexts.append(pack_negotiate_context(context, pad=idx != last_idx))

        return b"".join(
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
        offset: int = 0,
    ) -> "NegotiateRequest":
        view = memoryview(data)[offset:]

        dialect_count = struct.unpack("<H", view[2:4])[0]
        security_mode = SecurityModes(struct.unpack("<H", view[4:6])[0])
        capabilities = Capabilities(struct.unpack("<I", view[8:12])[0])
        client_guid = uuid.UUID(bytes_le=bytes(view[12:28]))
        context_offset = struct.unpack("<I", view[28:32])[0] - 64
        context_count = struct.unpack("<H", view[32:34])[0]

        dialect_view = view[36:]
        dialects: typing.List[Dialect] = []
        for _ in range(dialect_count):
            dialects.append(Dialect(struct.unpack("<H", dialect_view[:2])[0]))
            dialect_view = dialect_view[2:]

        context_view = view[context_offset:]
        contexts: typing.List[NegotiateContext] = []
        for _ in range(context_count):
            ctx, context_offset = unpack_negotiate_context(context_view)
            contexts.append(ctx)
            context_view = context_view[context_offset:]

        return NegotiateRequest(
            dialects=dialects,
            security_mode=security_mode,
            capabilities=capabilities,
            client_guid=client_guid,
            negotiate_contexts=contexts,
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
        system_time: int,
        server_start_time: int,
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

    def pack(self) -> bytes:
        sec_buffer = self.security_buffer or b""
        sec_buffer_offset = 129  # header + negotiate structure size
        negotiate_offset = 0
        padding_size = 0
        negotiate_contexts = []

        if self.negotiate_contexts:
            negotiate_offset = sec_buffer_offset + len(sec_buffer)
            padding_size = 8 - (negotiate_offset % 8 or 8)
            negotiate_offset += padding_size

            last_idx = len(self.negotiate_contexts) - 1
            for idx, context in enumerate(self.negotiate_contexts):
                negotiate_contexts.append(pack_negotiate_context(context, pad=idx != last_idx))

        return b"".join(
            [
                b"\x41\x00",  # StructureSize(64)
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
        offset: int = 0,
    ) -> "NegotiateResponse":
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
        sec_buffer_offset = struct.unpack("<H", view[56:58])[0] - 64
        sec_buffer_length = struct.unpack("<H", view[58:60])[0]
        context_offset = struct.unpack("<I", view[60:64])[0] - 64
        sec_buffer = bytes(view[sec_buffer_offset : sec_buffer_offset + sec_buffer_length])

        context_view = view[context_offset:]
        contexts: typing.List[NegotiateContext] = []
        for _ in range(context_count):
            ctx, context_offset = unpack_negotiate_context(context_view)
            contexts.append(ctx)
            context_view = context_view[context_offset:]

        return NegotiateResponse(
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
        )


@dataclasses.dataclass(frozen=True)
class SessionSetupRequest(SMBMessage):
    __slots__ = ("flags", "security_mode", "capabilities", "previous_session_id", "security_buffer")

    flags: SessionSetupFlags
    security_mode: SecurityModes
    capabilities: Capabilities
    previous_session_id: int
    security_buffer: bytes

    def __init__(
        self,
        *,
        flags: SessionSetupFlags,
        security_mode: SecurityModes,
        capabilities: Capabilities,
        previous_session_id: int,
        security_buffer: bytes,
    ) -> None:
        super().__init__(Command.SESSION_SETUP)
        object.__setattr__(self, "flags", flags)
        object.__setattr__(self, "security_mode", security_mode)
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "previous_session_id", previous_session_id)
        object.__setattr__(self, "security_buffer", security_buffer)


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


@dataclasses.dataclass(frozen=True)
class LogoffRequest(SMBMessage):
    __slots__ = ()

    def __init__(
        self,
    ) -> None:
        super().__init__(Command.LOGOFF)


@dataclasses.dataclass(frozen=True)
class LogoffResponse(SMBMessage):
    __slots__ = ()

    def __init__(
        self,
    ) -> None:
        super().__init__(Command.LOGOFF)


@dataclasses.dataclass(frozen=True)
class TreeConnectRequest(SMBMessage):
    __slots__ = ("flags", "path")

    flags: TreeConnectFlags
    path: str

    def __init__(
        self,
        flags: TreeConnectFlags,
        path: str,
    ) -> None:
        super().__init__(Command.TREE_CONNECT)
        object.__setattr__(self, "flags", flags)
        object.__setattr__(self, "path", path)


@dataclasses.dataclass(frozen=True)
class TreeConnectResponse(SMBMessage):
    __slots__ = ("share_type", "share_flags", "capabilities", "maximal_access")

    share_type: ShareType
    share_flags: ShareFlags
    capabilities: ShareCapabilities
    maximal_access: int

    def __init__(
        self,
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


@dataclasses.dataclass(frozen=True)
class TreeDisconnectRequest(SMBMessage):
    __slots__ = ()

    def __init__(
        self,
    ) -> None:
        super().__init__(Command.TREE_DISCONNECT)


@dataclasses.dataclass(frozen=True)
class TreeDisconnectResponse(SMBMessage):
    __slots__ = ()

    def __init__(
        self,
    ) -> None:
        super().__init__(Command.TREE_DISCONNECT)


MESSAGES: typing.Dict[Command, typing.Tuple[typing.Type[SMBMessage], typing.Type[SMBMessage]]] = {
    Command.NEGOTIATE: (NegotiateRequest, NegotiateResponse),
    Command.SESSION_SETUP: (SessionSetupRequest, SessionSetupResponse),
    Command.LOGOFF: (LogoffRequest, LogoffResponse),
    Command.TREE_CONNECT: (TreeConnectRequest, TreeConnectResponse),
    Command.TREE_DISCONNECT: (TreeDisconnectRequest, TreeDisconnectResponse),
}
