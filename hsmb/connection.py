# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import enum
import os
import typing
import uuid

from hsmb._config import SMBConfiguration, SMBRole
from hsmb._headers import (
    HeaderFlags,
    SMB1Header,
    SMB1HeaderFlags,
    SMB2HeaderAsync,
    SMB2HeaderSync,
)
from hsmb._messages import (
    Capabilities,
    Command,
    Dialect,
    NegotiateRequest,
    SecurityModes,
    SMB1NegotiateRequest,
    SMB1NegotiateResponse,
    SMBMessage,
)
from hsmb._negotiate_contexts import (
    Cipher,
    EncryptionCapabilities,
    HashAlgorithm,
    NegotiateContext,
    PreauthIntegrityCapabilities,
)


class SMBConnection:
    def __init__(
        self,
        config: SMBConfiguration,
        identifier: uuid.UUID,
    ) -> None:
        self.role = None
        self.config = config
        self.session_table: typing.Dict = {}
        self.preauth_session_table: typing.Dict = {}
        self.outstanding_requests: typing.Dict = {}
        self.sequence_window: typing.Dict = {}

        self._data_to_send = bytearray()

        self.our_identifier = identifier
        self.their_identifier = None
        self.our_capabilities = None
        self.their_capabilities = None
        self.our_security_mode = (
            SecurityModes.SIGNING_REQUIRED if config.require_message_signing else SecurityModes.SIGNING_ENABLED
        )
        self.their_security_mode = None
        self.our_name = None
        self.their_name = None

        self.max_transact_size = 0
        self.max_read_size = 0
        self.max_write_size = 0
        self.require_signing = False
        self.server_name = ""
        self.dialect = None

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

        header = SMB2HeaderSync(
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

        header = SMB2HeaderAsync(
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

    def negotiate(
        self,
        offered_dialects: typing.Optional[typing.List[Dialect]] = None,
        as_smb1: bool = False,
    ) -> None:
        if self.config.role != SMBRole.CLIENT:
            raise Exception("Only a client can start the negotiation")

        # FIXME: Test we haven't already negotiated.
        if not offered_dialects:
            offered_dialects = [Dialect.SMB202, Dialect.SMB210, Dialect.SMB300, Dialect.SMB302, Dialect.SMB311]

        highest_dialect = sorted(offered_dialects, reverse=True)[0]

        if as_smb1:
            smb1_dialects = ["SMB 2.???"]
            if Dialect.SMB202 in offered_dialects:
                smb1_dialects.insert(0, "SMB 2.002")

            smb1_negotiate = SMB1NegotiateRequest(dialects=smb1_dialects)
            smb1_header = SMB1Header(command=0x72, status=0, flags=SMB1HeaderFlags.NONE, pid=0, tid=0, uid=0, mid=0)
            self._data_to_send += smb1_header.pack()
            self._data_to_send += smb1_negotiate.pack()
            return

        client_guid = uuid.UUID(int=0)
        capabilities = Capabilities.NONE
        contexts: typing.List[NegotiateContext] = []

        if highest_dialect >= Dialect.SMB210:
            client_guid = self.our_identifier

        if highest_dialect >= Dialect.SMB300:
            capabilities = self.our_capabilities

        if highest_dialect >= Dialect.SMB311:
            salt = os.urandom(32)
            contexts.append(
                PreauthIntegrityCapabilities(
                    hash_algorithms=[HashAlgorithm.SHA512],
                    salt=salt,
                )
            )
            contexts.append(
                EncryptionCapabilities(
                    ciphers=[Cipher.AES256_GCM, Cipher.AES256_CCM, Cipher.AES128_GCM, Cipher.AES128_CCM],
                )
            )

        negotiate = NegotiateRequest(
            dialects=offered_dialects,
            security_mode=self.our_security_mode,
            capabilities=capabilities,
            client_guid=client_guid,
            negotiate_contexts=contexts,
        )
        self.send(negotiate)
