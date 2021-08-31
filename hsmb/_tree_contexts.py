# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import enum
import struct
import typing


class ContextType(enum.IntEnum):
    RESERVED = 0x0000
    REMOTED_IDENTITY = 0x0001


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

    context_type = ContextType(struct.unpack("<H", view[0:2])[0])
    context_length = struct.unpack("<H", view[2:4])[0]
    context_data = view[8 : 8 + context_length]

    context_cls: typing.Optional[typing.Type[TreeContext]] = {
        ContextType.REMOTED_IDENTITY: RemotedIdentity,
    }.get(context_type, None)
    if not context_cls:
        raise ValueError(f"Unknown tree connect context type {context_type}")

    return context_cls.unpack(context_data), 8 + context_length
