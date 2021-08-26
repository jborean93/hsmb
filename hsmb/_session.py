# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from hsmb._connection import SMBClientConnection
from hsmb._messages import (
    MESSAGES,
    Capabilities,
    LogoffRequest,
    SecurityModes,
    SessionSetupFlags,
    SessionSetupRequest,
)


class SMBClientSession:
    def __init__(
        self,
        connection: SMBClientConnection,
    ) -> None:
        self.session_id = 0
        self.tree_connect_table: typing.Dict[int, typing.Any] = {}
        self.session_key = b""
        self.signing_required = False
        self.connection = connection
        self.open_table: typing.Dict[int, typing.Any] = {}
        self.is_anonymous = False
        self.is_guest = False
        self.channel_list: typing.List = []
        self.encrypt_data = False
        self.encryption_key = b""
        self.decryption_key = b""
        self.signing_key = b""
        self.application_key = b""
        self.preauth_integrity_hash_value = b""
        self.full_session_key = b""

    def open(
        self,
        security_buffer: bytes,
    ) -> None:
        security_mode = (
            SecurityModes.SIGNING_REQUIRED
            if self.connection.config.require_message_signing
            else SecurityModes.SIGNING_ENABLED
        )
        req = SessionSetupRequest(
            flags=SessionSetupFlags.NONE,
            security_mode=security_mode,
            capabilities=Capabilities.DFS,
            channel=0,
            previous_session_id=0,
            security_buffer=security_buffer,
        )
        self.connection.send(req, session_id=self.session_id)

    def close(self) -> None:
        self.connection.send(LogoffRequest(), session_id=self.session_id)
