# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import os
import typing
import uuid

from hsmb._config import SMBClientConfig, SMBConfig, SMBRole, SMBServerConfig
from hsmb._headers import (
    HeaderFlags,
    SMB1Header,
    SMB1HeaderFlags,
    SMB2HeaderAsync,
    SMB2HeaderSync,
    SMBHeader,
    TransformHeader,
    unpack_header,
)
from hsmb._messages import (
    MESSAGES,
    Capabilities,
    Command,
    Dialect,
    NegotiateRequest,
    NegotiateResponse,
    SecurityModes,
    SMB1NegotiateRequest,
    SMB1NegotiateResponse,
    SMBMessage,
)
from hsmb._negotiate_contexts import (
    Cipher,
    CompressionAlgorithm,
    CompressionCapabilities,
    CompressionCapabilityFlags,
    EncryptionCapabilities,
    HashAlgorithm,
    NegotiateContext,
    NetnameNegotiate,
    PreauthIntegrityCapabilities,
    RdmaTransformCapabilities,
    RdmaTransformId,
    SigningAlgorithm,
    SigningCapabilities,
    TransportCapabilities,
    TransportCapabilityFlags,
)


class SMBConnection:
    def __init__(
        self,
        config: SMBConfig,
    ) -> None:
        self.config = config
        self.offered_dialects: typing.List[Dialect] = []
        self.dialect: typing.Optional[Dialect] = None
        self.our_identifier: typing.Optional[uuid.UUID] = None
        self.their_identifier: typing.Optional[uuid.UUID] = None
        self.our_security_mode = SecurityModes.NONE
        self.their_security_mode = SecurityModes.NONE
        self.our_capabilities = Capabilities.NONE
        self.their_capabilities = Capabilities.NONE
        self.salt: typing.Optional[bytes] = None

        self.session_table: typing.Dict = {}
        self.preauth_session_table: typing.Dict = {}
        self.outstanding_requests: typing.Dict = {}
        self.sequence_window: typing.Dict = {}

        self._data_to_send = bytearray()
        self._receive_buffer = bytearray()

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
            signature=b"\x00" * 16,
        )

        self._data_to_send += header.pack()
        self._data_to_send += message.pack()

    def send_smb1(
        self,
        message: SMBMessage,
    ) -> None:
        flags = SMB1HeaderFlags.EAS | SMB1HeaderFlags.NT_STATUS | SMB1HeaderFlags.UNICODE
        if isinstance(message, SMB1NegotiateResponse):
            flags |= SMB1HeaderFlags.REPLY

        header = SMB1Header(command=message.command.value, status=0, flags=flags, pid=0, tid=0, uid=0, mid=0)
        self._data_to_send += header.pack()
        self._data_to_send += message.pack()

    def data_to_send(
        self,
        amount: typing.Optional[int] = None,
    ) -> bytes:
        if amount:
            data = bytes(self._data_to_send[:amount])
            self._data_to_send = self._data_to_send[amount:]

        else:
            data = bytes(self._data_to_send)
            self._data_to_send = bytearray()

        return data

    def receive_data(
        self,
        data: bytes,
    ) -> None:
        self._receive_buffer += data

    def next_event(
        self,
    ) -> SMBMessage:
        header, offset = unpack_header(self._receive_buffer)

        if isinstance(header, TransformHeader):
            # TODO: Decrypt
            a = ""

        if isinstance(header, SMB1Header):
            if header.command != Command.SMB1_NEGOTIATE:
                raise Exception("Expecting SMB1 NEGOTIATE command")

            message_idx = 1 if header.flags & SMB1HeaderFlags.REPLY else 0
            command = Command(header.command)
            next_command = 0

        elif isinstance(header, (SMB2HeaderSync, SMB2HeaderAsync)):
            message_idx = 1 if header.flags & HeaderFlags.SERVER_TO_REDIR else 0
            command = header.command
            next_command = header.next_command

        else:
            raise Exception("Unknown header this shouldn't occur ever")

        message_cls = MESSAGES[command][message_idx]
        message, message_offset = message_cls.unpack(self._receive_buffer, offset)

        if next_command:
            self._receive_buffer = self._receive_buffer[next_command:]
        else:
            self._receive_buffer = self._receive_buffer[offset + message_offset :].lstrip(b"\x00")

        return message


class SMBClientConnection(SMBConnection):
    def __init__(
        self,
        config: SMBClientConfig,
    ) -> None:
        super().__init__(config)

    def negotiate(
        self,
        offered_dialects: typing.Optional[typing.List[Dialect]] = None,
        server_name: typing.Optional[str] = None,
        as_smb1: bool = False,
    ) -> None:
        # FIXME: Test we haven't already negotiated.
        if not offered_dialects:
            offered_dialects = [Dialect.SMB202, Dialect.SMB210, Dialect.SMB300, Dialect.SMB302, Dialect.SMB311]
        self.offered_dialects = offered_dialects
        highest_dialect = sorted(offered_dialects, reverse=True)[0]

        if as_smb1:
            smb1_dialects = ["SMB 2.???"]
            if Dialect.SMB202 in offered_dialects:
                smb1_dialects.insert(0, "SMB 2.002")

            smb1_negotiate = SMB1NegotiateRequest(dialects=smb1_dialects)
            self.send_smb1(smb1_negotiate)
            return

        self.our_security_mode = (
            SecurityModes.SIGNING_REQUIRED if self.config.require_message_signing else SecurityModes.SIGNING_ENABLED
        )

        if highest_dialect >= Dialect.SMB210:
            self.our_identifier = self.config.identifier

        if highest_dialect >= Dialect.SMB300:
            self.our_capabilities = Capabilities.NONE

        contexts: typing.List[NegotiateContext] = []
        if highest_dialect >= Dialect.SMB311:
            self.salt = os.urandom(32)
            contexts.append(
                PreauthIntegrityCapabilities(
                    hash_algorithms=[HashAlgorithm.SHA512],
                    salt=self.salt,
                )
            )

            if self.config.encryption:
                contexts.append(
                    EncryptionCapabilities(
                        ciphers=[Cipher.AES256_GCM, Cipher.AES256_CCM, Cipher.AES128_GCM, Cipher.AES128_CCM],
                    )
                )

            if self.config.compression:
                contexts.append(
                    CompressionCapabilities(
                        flags=CompressionCapabilityFlags.NONE,
                        compression_algorithms=[CompressionAlgorithm.LZ77_HUFFMAN],
                    )
                )

            # FIXME: Set based on the config values
            if False and self.config.rdma_transform:
                contexts.append(RdmaTransformCapabilities(rdma_transform_ids=[RdmaTransformId.NONE]))

            if server_name:
                contexts.append(NetnameNegotiate(net_name=server_name))

            contexts.append(
                SigningCapabilities(
                    signing_algorithms=[
                        SigningAlgorithm.AES_GMAC,
                        SigningAlgorithm.AES_CMAC,
                        SigningAlgorithm.HMAC_SHA256,
                    ]
                )
            )

            # FIXME: Do if underlying transport is QUIC
            if False and not self.config.encrypt_with_secure_transport:
                contexts.append(TransportCapabilities(flags=TransportCapabilityFlags.ACCEPT_TRANSPORT_LEVEL_SECURITY))

        negotiate = NegotiateRequest(
            dialects=offered_dialects,
            security_mode=self.our_security_mode,
            capabilities=self.our_capabilities,
            client_guid=self.our_identifier or uuid.UUID(int=0),
            negotiate_contexts=contexts,
        )
        self.send(negotiate)


class SMBServerConnection(SMBConnection):
    def __init__(
        self,
        config: SMBServerConfig,
        max_transact_size: int = 65536,
        max_read_size: int = 65536,
        max_write_size: int = 65536,
        security_buffer: typing.Optional[bytes] = None,
    ) -> None:
        super().__init__(config)
        self.max_transact_size = max_transact_size
        self.max_read_size = max_read_size
        self.max_write_size = max_write_size
        self._security_buffer = security_buffer

    def negotiate(self, message: typing.Union[SMB1NegotiateRequest, NegotiateRequest]) -> None:
        if isinstance(message, SMB1NegotiateRequest):
            if self._negotiate_smb1(message):
                return

        else:
            if self.dialect and self.dialect != Dialect.SMB2_WILDCARD:
                raise ValueError("Already negotiated")

            self.their_capabilities = message.capabilities
            self.their_identifier = message.client_guid

            if len(message.dialects) == 0:
                raise ValueError("Return STATUS_INVALID_PARAMETER")

            # FIXME: STATUS_NOT_SUPPORTED if no dialect match
            self.dialect = sorted(message.dialects, reverse=True)[0]

        nego_resp = NegotiateResponse(
            security_mode=self.our_security_mode,
            dialect_revision=self.dialect,
            server_guid=self.our_identifier,
            capabilities=self.our_capabilities,
            max_transact_size=self.max_transact_size,
            max_read_size=self.max_read_size,
            max_write_size=self.max_write_size,
            security_buffer=self._security_buffer,
            negotiate_contexts=[],
        )
        self.send(nego_resp, credits=1)

    def _negotiate_smb1(self, message: SMB1NegotiateRequest) -> bool:
        if "SMB 2.002" in message.dialects:
            self.dialect = Dialect.SMB202
        elif "SMB 2.???" in message.dialects:
            self.dialect = Dialect.SMB2_WILDCARD

        if self.dialect:
            self.our_security_mode = SecurityModes.SIGNING_ENABLED
            if self.config.require_message_signing:
                self.our_security_mode = SecurityModes.SIGNING_REQUIRED

            self.our_identifier = self.config.identifier
            self.our_capabilities = Capabilities.NONE
            # FIXME: Add DFS capability based on config
            # FIXME: Set LEASING, LARGE_MTU if wildcard
            # FIXME: Max sizes should be 65536 if 2.0.2
            return False

        else:
            resp = SMB1NegotiateResponse(selected_index=-1)
            self.send_smb1(resp)
            return True
