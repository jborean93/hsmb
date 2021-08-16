# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import enum
import typing
import uuid

from hsmb._negotiate_contexts import NegotiateContext


class Command(enum.IntEnum):
    negotiate = 0x0000
    session_setup = 0x0001
    logoff = 0x0002
    tree_connect = 0x0003
    tree_disconnect = 0x0004
    create = 0x0005
    close = 0x0006
    flush = 0x0007
    read = 0x0008
    write = 0x0009
    lock = 0x000A
    ioctl = 0x000B
    cancel = 0x000C
    echo = 0x000D
    query_directory = 0x000E
    change_notify = 0x000F
    query_info = 0x0010
    set_info = 0x0011
    oplock_break = 0x0011


class Dialect(enum.IntEnum):
    smb202 = 0x0202
    smb210 = 0x0210
    smb300 = 0x0300
    smb302 = 0x0302
    smb311 = 0x0311
    smb2_wildcard = 0x02FF


class SecurityModes(enum.IntFlag):
    signing_enabled = 0x0001
    signing_required = 0x0002


class Capabilities(enum.IntFlag):
    none = 0x00000000
    dfs = 0x00000001
    leasing = 0x00000002
    large_mtu = 0x00000004
    multi_channel = 0x00000008
    persistent_handles = 0x00000010
    directory_leasing = 0x00000020
    cap_encryption = 0x00000040


class SessionSetupFlags(enum.IntFlag):
    binding = 0x01


class SessionFlags(enum.IntFlag):
    is_guest = 0x0001
    is_null = 0x0002
    encrypt_data = 0x0004


class TreeConnectFlags(enum.IntFlag):
    cluster_reconnect = 0x0001
    redirect_to_owner = 0x0002
    extension_present = 0x0004


class ShareType(enum.IntEnum):
    disk = 0x01
    pipe = 0x02
    print = 0x03


class ShareFlags(enum.IntFlag):
    manual_caching = 0x0000000
    dfs = 0x00000001
    dfs_root = 0x00000002
    auto_caching = 0x00000010
    vdo_caching = 0x00000020
    no_caching = 0x00000030
    restrict_exclusive_opens = 0x00000100
    force_shared_delete = 0x00000200
    allow_namespace_caching = 0x00000400
    access_based_directory_enum = 0x00000400
    force_level2_oplock = 0x00001000
    enable_hash_v1 = 0x00002000
    enable_hash_v2 = 0x00004000
    encrypt_data = 0x00008000
    identity_remoting = 0x00040000
    compress_data = 0x00100000


class ShareCapabilities(enum.IntFlag):
    dfs = 0x00000008
    continuous_availability = 0x00000010
    scaleout = 0x00000020
    cap_cluster = 0x00000040
    asymmetrix = 0x00000080
    redirect_to_owner = 0x00000100


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
        super().__init__(Command.negotiate)
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
        super().__init__(Command.negotiate)
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
        super().__init__(Command.session_setup)
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
        super().__init__(Command.session_setup)
        object.__setattr__(self, "session_flags", session_flags)
        object.__setattr__(self, "security_buffer", security_buffer)


@dataclasses.dataclass(frozen=True)
class LogoffRequest(SMBMessage):
    __slots__ = ()

    def __init__(
        self,
    ) -> None:
        super().__init__(Command.logoff)


@dataclasses.dataclass(frozen=True)
class LogoffResponse(SMBMessage):
    __slots__ = ()

    def __init__(
        self,
    ) -> None:
        super().__init__(Command.logoff)


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
        super().__init__(Command.tree_connect)
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
        super().__init__(Command.tree_connect)
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
        super().__init__(Command.tree_disconnect)


@dataclasses.dataclass(frozen=True)
class TreeDisconnectResponse(SMBMessage):
    __slots__ = ()

    def __init__(
        self,
    ) -> None:
        super().__init__(Command.tree_disconnect)


EVENTS: typing.Dict[Command, typing.Tuple[typing.Type[SMBMessage], typing.Type[SMBMessage]]] = {
    Command.negotiate: (NegotiateRequest, NegotiateResponse),
    Command.session_setup: (SessionSetupRequest, SessionSetupResponse),
    Command.logoff: (LogoffRequest, LogoffResponse),
    Command.tree_connect: (TreeConnectRequest, TreeConnectResponse),
    Command.tree_disconnect: (TreeDisconnectRequest, TreeDisconnectResponse),
}
