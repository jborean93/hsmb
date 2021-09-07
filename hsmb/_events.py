# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from hsmb._create import CreateResponse
from hsmb._exceptions import ProtocolError
from hsmb._header import SMB2Header
from hsmb._messages import SMBMessage
from hsmb._negotiate import NegotiateResponse
from hsmb._session import SessionSetupResponse
from hsmb._tree import TreeConnectResponse

if typing.TYPE_CHECKING:
    from hsmb._client import (
        ClientApplicationOpenFile,
        ClientConnection,
        ClientSession,
        ClientTreeConnect,
    )

MessageType = typing.TypeVar("MessageType", bound=SMBMessage)


class Event:
    pass


class ErrorReceived(Event):
    def __init__(
        self,
        header: SMB2Header,
        error: ProtocolError,
    ) -> None:
        self.header = header
        self.error = error

    @property
    def message_id(self) -> int:
        return self.header.message_id

    def __repr__(self) -> str:
        return (
            f"<ErrorReceived command:{self.header.command!s} status:0x{self.header.status:8X} "
            f"error:{type(self.error).__name__} {self.error!s}>"
        )


class MessageReceived(Event, typing.Generic[MessageType]):
    def __init__(
        self,
        header: SMB2Header,
        message: MessageType,
        data_available: bool = False,
    ) -> None:
        self.header = header
        self.message = message
        self.data_available = data_available

    @property
    def message_id(self) -> int:
        return self.header.message_id

    def __repr__(self) -> str:
        command = getattr(self.header, "command", "UNKNOWN")
        return f"<MessageReceived {type(self.header).__name__} {command!s}>"


class ProtocolNegotiated(MessageReceived[NegotiateResponse]):
    def __init__(
        self,
        header: SMB2Header,
        message: NegotiateResponse,
        connection: "ClientConnection",
    ) -> None:
        super().__init__(header, message)
        self.connection = connection

    @property
    def token(self) -> typing.Optional[bytes]:
        return self.message.security_buffer if self.message.security_buffer else None

    def __repr__(self) -> str:
        return f"<ProtocolNegotiated {self.message.dialect_revision!s} server_guid:{self.message.server_guid!s}>"


class SessionProcessingRequired(MessageReceived[SessionSetupResponse]):
    def __init__(
        self,
        header: SMB2Header,
        message: SessionSetupResponse,
    ) -> None:
        super().__init__(header, message)

    @property
    def session_id(self) -> int:
        return self.header.session_id

    @property
    def token(self) -> bytes:
        return self.message.security_buffer

    def __repr__(self) -> str:
        return f"<SessionProcessingRequired session_id:{self.session_id}>"


class SessionAuthenticated(MessageReceived[SessionSetupResponse]):
    def __init__(
        self,
        header: SMB2Header,
        message: SessionSetupResponse,
        session: "ClientSession",
        raw_data: bytes,
    ) -> None:
        super().__init__(header, message)
        self.session = session
        self.raw_data = raw_data

    @property
    def session_id(self) -> int:
        return self.session.session_id

    @property
    def token(self) -> typing.Optional[bytes]:
        return self.message.security_buffer if self.message.security_buffer else None

    def __repr__(self) -> str:
        return f"<SessionAuthenticated session_id:{self.session_id}>"


class TreeConnected(MessageReceived[TreeConnectResponse]):
    def __init__(
        self,
        header: SMB2Header,
        message: TreeConnectResponse,
        tree: "ClientTreeConnect",
    ) -> None:
        super().__init__(header, message)
        self.tree = tree

    def __repr__(self) -> str:
        return (
            f"<TreeConnected name:{self.tree.share_name} tree_id:{self.tree.tree_connect_id} "
            f"session_id:{self.header.session_id}>"
        )


class FileOpened(MessageReceived[CreateResponse]):
    def __init__(
        self,
        header: SMB2Header,
        message: CreateResponse,
        open: "ClientApplicationOpenFile",
    ) -> None:
        super().__init__(header, message)
        self.open = open

    @property
    def file_id(self) -> bytes:
        return self.open.file_id

    def __repr__(self) -> str:
        return f"<FileOpened name:{self.open.file_name}>"
