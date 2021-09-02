# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from hsmb._messages import SMB2Header, SMBHeader, SMBMessage
from hsmb._negotiate import NegotiateResponse
from hsmb._session import SessionSetupResponse
from hsmb._tree import TreeConnectResponse

if typing.TYPE_CHECKING:
    from hsmb._client import ClientConnection, ClientSession, ClientTreeConnect

HeaderType = typing.TypeVar("HeaderType", bound=SMBHeader)
MessageType = typing.TypeVar("MessageType", bound=SMBMessage)


class Event:
    pass


class MessageReceived(Event, typing.Generic[HeaderType, MessageType]):
    def __init__(
        self,
        header: HeaderType,
        message: MessageType,
        data_available: bool = False,
    ) -> None:
        self.header = header
        self.message = message
        self.data_available = data_available

    def __repr__(self) -> str:
        command = getattr(self.header, "command", "UNKNOWN")
        return f"<MessageReceived {type(self.header).__name__} {command!s}>"


class ProtocolNegotiated(MessageReceived[SMB2Header, NegotiateResponse]):
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


class SessionProcessingRequired(Event):
    def __init__(
        self,
        header: SMB2Header,
        token: typing.Optional[bytes],
    ) -> None:
        self.header = header
        self.token = token

    @property
    def session_id(self) -> int:
        return self.header.session_id

    def __repr__(self) -> str:
        return f"<SessionProcessingRequired session_id:{self.session_id}>"


class SessionAuthenticated(MessageReceived[SMB2Header, SessionSetupResponse]):
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


class TreeConnected(MessageReceived[SMB2Header, TreeConnectResponse]):
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
