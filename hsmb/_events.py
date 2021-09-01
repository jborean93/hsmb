# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from hsmb._client import ClientConnection, ClientSession, ClientTreeConnect
from hsmb._headers import SMB2Header, SMBHeader
from hsmb._messages import (
    NegotiateResponse,
    SessionSetupResponse,
    SMBMessage,
    TreeConnectResponse,
)

HeaderType = typing.TypeVar("HeaderType", bound=SMBHeader)
MessageType = typing.TypeVar("MessageType", bound=SMBMessage)


class Event:
    pass


class MessageReceived(Event, typing.Generic[HeaderType, MessageType]):
    def __init__(
        self,
        header: HeaderType,
        message: MessageType,
    ) -> None:
        self.header = header
        self.message = message


class ProtocolNegotiated(MessageReceived[SMB2Header, NegotiateResponse]):
    def __init__(
        self,
        header: SMB2Header,
        message: NegotiateResponse,
        connection: ClientConnection,
    ) -> None:
        super().__init__(header, message)
        self.connection = connection

    @property
    def token(self) -> typing.Optional[bytes]:
        return self.message.security_buffer if self.message.security_buffer else None


class SessionProcessingRequired(MessageReceived[SMB2Header, SessionSetupResponse]):
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
    def token(self) -> typing.Optional[bytes]:
        return self.message.security_buffer if self.message.security_buffer else None


class SessionAuthenticated(MessageReceived[SMB2Header, SessionSetupResponse]):
    def __init__(
        self,
        header: SMB2Header,
        message: SessionSetupResponse,
        session: ClientSession,
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


class TreeConnected(MessageReceived[SMB2Header, TreeConnectResponse]):
    def __init__(
        self,
        header: SMB2Header,
        message: TreeConnectResponse,
        tree: ClientTreeConnect,
    ) -> None:
        super().__init__(header, message)
        self.tree = tree
