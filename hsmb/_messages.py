# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import enum
import typing
import uuid

from hsmb._negotiate_contexts import NegotiateContext


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
    def unpack(self, data: bytes) -> "SMBMessage":
        raise NotImplementedError()


@dataclasses.dataclass(frozen=True)
class NegotiateRequest(SMBMessage):
    __slots__ = ("dialects", "security_mode", "capabilities", "client_guid", "negotiate_contexts")

    dialects: typing.List[Dialect]
    security_mode: SecurityModes
    capabilities: Capabilities
    client_guid: uuid.UUID
    negotiate_contexts: typing.List

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
        return b""

    @classmethod
    def unpack(self, data: bytes) -> "NegotiateRequest":
        raise NotImplementedError()


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
        negotiate_contexts: typing.Optional[NegotiateContext] = None,
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
