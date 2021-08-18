# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import enum
import typing
import uuid

from hsmb._config import SMBConfiguration, SMBRole
from hsmb._headers import HeaderFlags, PacketHeaderAsync, PacketHeaderSync
from hsmb._messages import (
    Capabilities,
    Command,
    Dialect,
    NegotiateRequest,
    SecurityModes,
    SMBMessage,
)


class SMBConnection:
    def __init__(
        self,
        config: SMBConfiguration,
        identifier: uuid.UUID,
    ) -> None:
        self.config = config
        self.identifier = identifier
        self._data_to_send = bytearray()

    def send(
        self,
        message: SMBMessage,
        channel_sequence: int = 0,
        status: int = 0,
        credits: int = 0,
        related: bool = False,
        priority: typing.Optional[int] = 0,
        session_id: int = 0,
        tree_id: int = 0,
        final: bool = True,
    ) -> None:
        flags = HeaderFlags.NONE

        if self.config.role == SMBRole.CLIENT:
            if status:
                raise ValueError("Client cannot set status")

        else:
            if channel_sequence:
                raise ValueError("Server cannot set channel sequence")

            flags |= HeaderFlags.SERVER_TO_REDIR

        if related:
            flags |= HeaderFlags.RELATED_OPERATIONS

        if priority is not None:
            if priority < 0 or priority > 7:
                raise ValueError("Priority must be between 0 and 7")
            flags |= priority << 4

        # FIXME
        credit_charge = 0
        next_command = 0
        message_id = 0

        header = PacketHeaderSync(
            credit_charge=credit_charge,
            channel_sequence=channel_sequence,
            status=status,
            command=message.command,
            credits=credits,
            flags=flags,
            next_command=next_command,
            message_id=message_id,
            tree_id=tree_id,
            session_id=session_id,
            signature=b"\x00" * 16,
        ).pack()

        self._data_to_send += header
        self._data_to_send += message.pack()

    def send_async(
        self,
        message: SMBMessage,
        channel_sequence: int = 0,
        status: int = 0,
        credits: int = 0,
        related: bool = False,
        priority: typing.Optional[int] = 0,
        session_id: int = 0,
        async_id: int = 0,
        final: bool = True,
    ) -> None:
        flags = HeaderFlags.ASYNC_COMMAND

        if self.config.role == SMBRole.CLIENT:
            if status:
                raise ValueError("Client cannot set status")

        else:
            if channel_sequence:
                raise ValueError("Server cannot set channel sequence")

            flags |= HeaderFlags.SERVER_TO_REDIR

        if related:
            flags |= HeaderFlags.RELATED_OPERATIONS

        if priority is not None:
            if priority < 0 or priority > 7:
                raise ValueError("Priority must be between 0 and 7")
            flags |= priority << 4

        # FIXME
        credit_charge = 0
        next_command = 0
        message_id = 0

        header = PacketHeaderAsync(
            credit_charge=credit_charge,
            channel_sequence=channel_sequence,
            status=status,
            command=message.command,
            credits=credits,
            flags=flags,
            next_command=next_command,
            message_id=message_id,
            async_id=async_id,
            session_id=session_id,
            signature=b"",
        )

        self._data_to_send += header.pack()
        self._data_to_send += message.pack()

    def data_to_send(
        self,
        amount: typing.Optional[int] = None,
    ) -> bytes:
        return b""

    def receive_data(
        self,
        data: bytes,
    ) -> None:
        a = ""

    def next_event(
        self,
    ) -> None:
        return
