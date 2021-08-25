# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import dataclasses
import datetime
import enum
import os
import typing
import uuid

from hsmb._config import (
    ClientServer,
    SMBClientConfig,
    SMBConfig,
    SMBRole,
    SMBServerConfig,
)
from hsmb._events import Event, RequestReceived, ResponseReceived
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
    ContextType,
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


class TransportIdentifier(enum.Enum):
    UNKNOWN = enum.auto()
    DIRECT_TCP = enum.auto()
    NETBIOS_TCP = enum.auto()
    QUIC = enum.auto()


@dataclasses.dataclass
class PendingRequest:
    message: SMBMessage
    async_id: int = 0
    cancel_id: uuid.UUID = dataclasses.field(default_factory=uuid.uuid4)
    timestamp: datetime.datetime = dataclasses.field(default_factory=datetime.datetime.now)
    buffer_descriptor_list: typing.List = dataclasses.field(default_factory=list)


class SMBClientConnection:
    def __init__(
        self,
        config: SMBClientConfig,
        server_name: str,
        transport_identifier: TransportIdentifier = TransportIdentifier.UNKNOWN,
    ) -> None:
        self.config = config
        self._data_to_send = bytearray()
        self._receive_buffer = bytearray()

        self.transport_identifier = transport_identifier

        self.session_table: typing.Dict = {}
        self.preauth_session_table: typing.Dict = {}
        self.outstanding_requests: typing.Dict[int, PendingRequest] = {}
        self.sequence_window: typing.List[typing.Tuple[int, int]] = [(0, 1)]
        self.gss_negotiate_token: typing.Optional[bytes] = None
        self.max_transact_size = 65536
        self.max_read_size = 65536
        self.max_write_size = 65536
        self.server_guid = uuid.UUID(int=0)
        self.require_signing = False
        self.server_name = server_name

        # SMB 2.1
        self.dialect = Dialect.UNKNOWN
        self.supports_file_leasing = False
        self.supports_multi_credit = False
        self.client_guid = uuid.UUID(int=0)

        # SMB 3.x
        self.supports_directory_leasing = False
        self.supports_multi_channel = False
        self.supports_persistent_handles = False
        self.supports_encryption = False
        self.client_capabilities = Capabilities.NONE
        self.server_capabilities = Capabilities.NONE
        self.client_security_mode = SecurityModes.NONE
        self.server_security_mode = SecurityModes.NONE
        self.server: typing.Optional[ClientServer] = None
        self.offered_dialects: typing.List[Dialect] = []

        # SMB 3.1.1
        self.preauth_integirty_hash_id: typing.Optional[HashAlgorithm] = None
        self.preauth_integrity_hash_value = bytearray()
        self.cipher_id: typing.Optional[Cipher] = None
        self.compression_ids: typing.List[CompressionAlgorithm] = []
        self.supports_chained_compression = False
        self.rdma_transform_ids: typing.List[RdmaTransformId] = []
        self.signing_algorithm_id: typing.Optional[SigningAlgorithm] = None
        self.accept_transport_security = False

    def send(
        self,
        message: SMBMessage,
        channel_sequence: int = 0,
        credits: int = 0,
        related: bool = False,
        priority: typing.Optional[int] = 0,
        session_id: int = 0,
        tree_id: int = 0,
        final: bool = True,
    ) -> None:
        flags = HeaderFlags.NONE

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
            status=0,
            command=message.command,
            credits=credits,
            flags=flags,
            next_command=next_command,
            message_id=message_id,
            tree_id=tree_id,
            session_id=session_id,
            signature=b"\x00" * 16,
        )
        self.outstanding_requests[message_id] = PendingRequest(message=message)

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
    ) -> typing.Optional[Event]:
        header, offset = unpack_header(self._receive_buffer)

        if isinstance(header, TransformHeader):
            raise Exception("FIXME decryption")

        command: Command
        if isinstance(header, SMB1Header):
            if header.command != Command.SMB1_NEGOTIATE:
                raise Exception("Expecting SMB1 NEGOTIATE command")

            command = Command(header.command)
            next_command = 0
            message_id = 0

        elif isinstance(header, (SMB2HeaderSync, SMB2HeaderAsync)):
            command = header.command
            next_command = header.next_command
            message_id = header.message_id

        else:
            raise Exception("Unknown header this shouldn't occur ever")

        message_cls = MESSAGES[command][1]
        message, message_offset = message_cls.unpack(self._receive_buffer, offset)

        if next_command:
            self._receive_buffer = self._receive_buffer[next_command:]
        else:
            # In case the message still contained padded bytes strip off the remaining NULL bytes.
            self._receive_buffer = self._receive_buffer[offset + message_offset :].lstrip(b"\x00")

        request = self.outstanding_requests[message_id]
        process_func = getattr(self, f"_process_{command.name.lower()}", None)
        if process_func:
            process_func(request, message)

        return ResponseReceived(header, message)

    def open(
        self,
        offered_dialects: typing.Optional[typing.List[Dialect]] = None,
        as_smb1: bool = False,
    ) -> None:
        if not offered_dialects:
            offered_dialects = [
                d for d in Dialect if d not in [Dialect.UNKNOWN, Dialect.SMB2_WILDCARD] and d <= self.config.max_dialect
            ]
        self.offered_dialects = offered_dialects
        highest_dialect = sorted(offered_dialects, reverse=True)[0]

        if as_smb1:
            smb1_dialects = ["SMB 2.???"]
            if Dialect.SMB202 in offered_dialects:
                smb1_dialects.insert(0, "SMB 2.002")

            negotiate = SMB1NegotiateRequest(dialects=smb1_dialects)

            flags = SMB1HeaderFlags.EAS | SMB1HeaderFlags.NT_STATUS | SMB1HeaderFlags.UNICODE
            header = SMB1Header(command=negotiate.command.value, status=0, flags=flags, pid=0, tid=0, uid=0, mid=0)
            self._data_to_send += header.pack()
            self._data_to_send += negotiate.pack()

            return

        self.our_security_mode = (
            SecurityModes.SIGNING_REQUIRED if self.config.require_message_signing else SecurityModes.SIGNING_ENABLED
        )

        if highest_dialect >= Dialect.SMB210:
            self.our_identifier = self.config.client_guid

        if highest_dialect >= Dialect.SMB300:
            self.our_capabilities = Capabilities.NONE

        contexts: typing.List[NegotiateContext] = []
        if highest_dialect >= Dialect.SMB311:
            if not self.config.registered_hash_algorithms:
                raise Exception("No registered hash algorithms available")

            contexts.append(
                PreauthIntegrityCapabilities(
                    hash_algorithms=[h.algorithm_id() for h in self.config.registered_hash_algorithms],
                    salt=os.urandom(32),
                )
            )

            if self.config.is_encryption_supported and self.config.registered_ciphers:
                contexts.append(
                    EncryptionCapabilities(
                        ciphers=[c.cipher_id() for c in self.config.registered_ciphers],
                    )
                )

            if self.config.is_compression_supported and self.config.registered_compressors:
                contexts.append(
                    CompressionCapabilities(
                        flags=CompressionCapabilityFlags.NONE,
                        compression_algorithms=[c.compression_id() for c in self.config.registered_compressors],
                    )
                )

            # FIXME: Set based on the config values
            if False and self.config.is_rdma_transform_supported:
                contexts.append(RdmaTransformCapabilities(rdma_transform_ids=[RdmaTransformId.NONE]))

            if self.server_name:
                contexts.append(NetnameNegotiate(net_name=self.server_name))

            if self.config.registered_signing_algorithms:
                contexts.append(
                    SigningCapabilities(
                        signing_algorithms=[s.signing_id() for s in self.config.registered_signing_algorithms]
                    )
                )

            if (
                self.transport_identifier == TransportIdentifier.QUIC
                and not self.config.disable_encryption_over_secure_transport
            ):
                contexts.append(TransportCapabilities(flags=TransportCapabilityFlags.ACCEPT_TRANSPORT_LEVEL_SECURITY))

        self.send(
            NegotiateRequest(
                dialects=self.offered_dialects,
                security_mode=self.our_security_mode,
                capabilities=self.our_capabilities,
                client_guid=self.our_identifier,
                negotiate_contexts=contexts,
            )
        )

    def close(self) -> None:
        pass

    def _process_negotiate(
        self,
        request: PendingRequest,
        message: NegotiateResponse,
    ) -> None:
        self.max_transact_size = message.max_transact_size
        self.max_read_size = message.max_read_size
        self.max_write_size = message.max_write_size
        self.their_guid = message.server_guid
        self.gss_negotiate_token = message.security_buffer
        self.require_signing = bool(message.security_mode & SecurityModes.SIGNING_REQUIRED)

        if message.dialect_revision == Dialect.SMB2_WILDCARD:
            self.open(self.offered_dialects, as_smb1=False)
            return

        if message.dialect_revision not in self.offered_dialects:
            raise Exception("Received dialect we didn't ask for")

        if message.dialect_revision >= Dialect.SMB210:
            self.supports_file_leasing = bool(message.capabilities & Capabilities.LEASING)
            self.supports_multi_credit = bool(message.capabilities & Capabilities.LARGE_MTU)

        if message.dialect_revision >= Dialect.SMB300:
            self.supports_directory_leasing = bool(message.capabilities & Capabilities.DIRECTORY_LEASING)
            self.supports_multi_channel = bool(message.capabilities & Capabilities.MULTI_CHANNEL)

            if message.dialect_revision < Dialect.SMB311:
                self.supports_encryption = bool(message.capabilities & Capabilities.ENCRYPTION)

            self.their_capabilities = message.capabilities
            self.their_security_mode = message.security_mode

            if self.server_name:
                self.server = self.config.server_list.setdefault(
                    self.server_name,
                    ClientServer(
                        server_guid=message.server_guid,
                        dialect_revision=message.dialect_revision,
                        capabilities=message.capabilities,
                        security_mode=message.security_mode,
                        address_list=[],
                        server_name=self.server_name,
                    ),
                )
                # FIXME: Verify all this

        if message.dialect_revision >= Dialect.SMB311:
            found_contexts: typing.Set[ContextType] = set()
            for context in message.negotiate_contexts:
                if context.context_type in found_contexts:
                    raise Exception(f"Found multiple context {context.context_type}")

                found_contexts.add(context.context_type)

                if isinstance(context, PreauthIntegrityCapabilities):
                    if len(context.hash_algorithms) != 1:
                        raise Exception(f"Found {len(context.hash_algorithms)} algorithms, expecting 1")

                    # TODO: Verify it's in the original request
                    self.preauth_integirty_hash_id = context.hash_algorithms[0]

                elif isinstance(context, EncryptionCapabilities):
                    if len(context.ciphers) != 1:
                        raise Exception(f"Found {len(context.ciphers)} ciphers, expecting 1")
                    # TODO: Verify cipher is in the original request
                    if context.ciphers[0] != 0:
                        self.supports_encryption = True
                        self.cipher_id = context.ciphers[0]

                        if self.server:
                            self.server.cipher_id = context.ciphers[0]

            if ContextType.PREAUTH_INTEGRITY_CAPABILITIES not in found_contexts:
                raise Exception("Was expecting at least 1 preauth int cap")

            # FIXME
            self.preauth_integrity_hash_value += b""


"""
class SMBServerConnection(SMBConnection[SMBServerConfig]):

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
        self.security_buffer = security_buffer

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
            security_buffer=self.security_buffer,
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
"""
