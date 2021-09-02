# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import enum
import struct
import typing

from hsmb._exceptions import MalformedPacket
from hsmb._messages import MESSAGES, Command, SMBMessage


class ContextType(enum.IntEnum):
    RESERVED = 0x0000
    REMOTED_IDENTITY = 0x0001


class ShareCapabilities(enum.IntFlag):
    DFS = 0x00000008
    CONTINUOUS_AVAILABILITY = 0x00000010
    SCALEOUT = 0x00000020
    CAP_CLUSTER = 0x00000040
    ASYMMETRIX = 0x00000080
    REDIRECT_TO_OWNER = 0x00000100


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


class ShareType(enum.IntEnum):
    UNKNOWN = 0x00
    DISK = 0x01
    PIPE = 0x02
    PRINT = 0x03


class TreeConnectFlags(enum.IntFlag):
    NONE = 0x0000
    CLUSTER_RECONNECT = 0x0001
    REDIRECT_TO_OWNER = 0x0002
    EXTENSION_PRESENT = 0x0004


@dataclasses.dataclass(frozen=True)
class TreeContext:
    __slots__ = ("context_type",)

    context_type: ContextType

    def pack(self) -> bytearray:
        raise NotImplementedError()

    @classmethod
    def unpack(
        cls,
        data: typing.Union[bytes, bytearray, memoryview],
        offset: int = 0,
    ) -> "TreeContext":
        raise NotImplementedError()


@dataclasses.dataclass(frozen=True)
class RemotedIdentity(TreeContext):
    __slots__ = ("ticket_type", "user_name")

    ticket_type: int
    username: str

    def __init__(
        self,
        *,
        ticket_type: int,
        username: str,
    ) -> None:
        super().__init__(ContextType.REMOTED_IDENTITY)
        object.__setattr__(self, "username", username)
        object.__setattr__(self, "ticket_type", ticket_type)


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
        tree_contexts = bytearray()

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
                tree_contexts += context_data

                context_padding_size = 8 - (len(context_data) % 8 or 8)
                if idx != last_idx and context_padding_size:
                    tree_contexts += b"\x00" * context_padding_size

        return bytearray().join(
            [
                b"\x09\x00",
                self.flags.to_bytes(2, byteorder="little"),
                path_offset.to_bytes(2, byteorder="little"),
                len(b_path).to_bytes(2, byteorder="little"),
                extension_info,
                b_path,
                (b"\x00" * padding_size),
                tree_contexts,
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

        if len(view) < 8:
            raise MalformedPacket("Tree connect request payload is too small")

        flags = TreeConnectFlags(struct.unpack("<H", view[2:4])[0])
        path_offset = struct.unpack("<H", view[4:6])[0] - offset_from_header
        path_length = struct.unpack("<H", view[6:8])[0]
        path_name = bytes(view[path_offset : path_offset + path_length]).decode("utf-16-le")
        end_idx = path_offset + path_length

        contexts: typing.List[TreeContext] = []
        if flags & TreeConnectFlags.EXTENSION_PRESENT:
            if len(view) < 14:
                raise MalformedPacket("Tree connect request payload is too small")

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
                self.share_type.to_bytes(1, byteorder="little"),
                b"\x00",  # Reserved
                self.share_flags.to_bytes(4, byteorder="little"),
                self.capabilities.to_bytes(4, byteorder="little"),
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

        if len(view) < 16:
            raise MalformedPacket("Tree connect response payload is too small")

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
            raise MalformedPacket("Tree disconnect request payload is too small")

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
            raise MalformedPacket("Tree disconnect response payload is too small")

        return TreeDisconnectResponse(), 4


def pack_tree_context(
    context: TreeContext,
) -> bytearray:
    """Pack the Tree Connect Context object.

    Packs the Tree Connect context object into bytes. The value is packed
    according to the structure defined at
    `SMB2 TREE_CONNECT_CONTEXT Structure`_.

    Args:
        context: The context to pack.

    Returns:
        bytes: The packed context.

    .. _SMB2 TREE_CONNECT_CONTEXT Structure:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/06eaaabc-caca-4776-9daf-82439e90dacd
    """
    context_data = context.pack()

    return bytearray().join(
        [
            context.context_type.to_bytes(2, byteorder="little"),
            len(context_data).to_bytes(2, byteorder="little"),
            b"\x00\x00\x00\x00",  # Reserved
            context_data,
        ]
    )


def unpack_tree_context(
    data: typing.Union[bytes, bytearray, memoryview],
) -> typing.Tuple[TreeContext, int]:
    """Unpack the Tree Connect Context bytes.

    Unpacks the Tree Connect context bytes value to the object it represents.
    The value is unpacked according to the structure defined at
    `SMB2 TREE_CONNECT_CONTEXT Structure`_.

    Args:
        data: The data to unpack.

    Returns:
        Tuple[TreeContext, int]: The unpacked context and the length of the
        context (including padding to the 8 byte boundary) that was unpacked.

    .. _SMB2 TREE_CONNECT_CONTEXT Structure:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/06eaaabc-caca-4776-9daf-82439e90dacd
    """
    view = memoryview(data)

    if len(view) < 8:
        raise MalformedPacket("Tree context payload is too small")

    context_type = ContextType(struct.unpack("<H", view[0:2])[0])
    context_length = struct.unpack("<H", view[2:4])[0]
    context_data = view[8 : 8 + context_length]

    if len(view) < (8 + context_length):
        raise MalformedPacket("Tree context payload is too small")

    context_cls: typing.Optional[typing.Type[TreeContext]] = {
        ContextType.REMOTED_IDENTITY: RemotedIdentity,
    }.get(context_type, None)
    if not context_cls:
        raise MalformedPacket(f"Unknown tree context type {context_type}")

    return context_cls.unpack(context_data), 8 + context_length


MESSAGES[Command.TREE_CONNECT] = (TreeConnectRequest, TreeConnectResponse)
MESSAGES[Command.TREE_DISCONNECT] = (TreeDisconnectRequest, TreeDisconnectResponse)
