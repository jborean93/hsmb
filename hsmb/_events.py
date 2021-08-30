# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)


from hsmb._headers import SMBHeader
from hsmb._messages import SMBMessage


class Event:
    pass


class RequestReceived(Event):
    def __init__(
        self,
        header: SMBHeader,
        message: SMBMessage,
    ) -> None:
        self.header = header
        self.message = message


class ResponseReceived(Event):
    def __init__(
        self,
        header: SMBHeader,
        message: SMBMessage,
    ) -> None:
        self.header = header
        self.message = message


class SecurityTokenReceived(Event):
    def __init__(
        self,
        session_id: int,
        token: bytes,
        require_session_key: bool,
    ) -> None:
        self.session_id = session_id
        self.token = token
        self.require_session_key = require_session_key
