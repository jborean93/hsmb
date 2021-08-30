# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import dataclasses
import datetime
import enum
import hashlib
import hmac
import os
import typing
import uuid

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

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
    SMB2Header,
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
    CipherBase,
    CompressionAlgorithmBase,
    CompressionCapabilities,
    CompressionCapabilityFlags,
    ContextType,
    EncryptionCapabilities,
    HashAlgorithmBase,
    NegotiateContext,
    NetnameNegotiate,
    PreauthIntegrityCapabilities,
    RdmaTransformCapabilities,
    RdmaTransformId,
    SigningAlgorithmBase,
    SigningCapabilities,
    TransportCapabilities,
    TransportCapabilityFlags,
)

if typing.TYPE_CHECKING:
    from hsmb._session import SMBClientSession

MessageType = typing.TypeVar("MessageType", bound=SMBMessage)
ResponseCallback = typing.Optional[typing.Callable[[SMB2Header, MessageType, memoryview], typing.Optional[Event]]]


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
    receive_callback: ResponseCallback = None


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

        self.session_table: typing.Dict[int, "SMBClientSession"] = {}
        self.preauth_session_table: typing.Dict[int, "SMBClientSession"] = {}
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
        self.preauth_integrity_hash_id: typing.Optional[HashAlgorithmBase] = None
        self.preauth_integrity_hash_value = b""
        self.cipher_id: typing.Optional[CipherBase] = None
        self.compression_ids: typing.List[CompressionAlgorithmBase] = []
        self.supports_chained_compression = False
        self.rdma_transform_ids: typing.List[RdmaTransformId] = []
        self.signing_algorithm_id: typing.Optional[SigningAlgorithmBase] = None
        self.accept_transport_security = False

    def create_header(
        self,
        message: SMBMessage,
        channel_sequence: int = 0,
        credits: int = 0,
        related: bool = False,
        priority: typing.Optional[int] = None,
        session_id: int = 0,
        tree_id: int = 0,
        final: bool = True,
        callback: ResponseCallback = None,
    ) -> None:
        flags = HeaderFlags.NONE

        if related:
            flags |= HeaderFlags.RELATED_OPERATIONS

        if priority is not None:
            if priority < 0 or priority > 7:
                raise ValueError("Priority must be between 0 and 7")
            flags |= priority << 4

        next_command = 0

        credit_charge: int
        message_id: int
        if message.command == Command.CANCEL:
            # FIXME: This should be the id of the request being cancelled
            message_id = 0
            credit_charge = 0

        else:
            if self.supports_multi_credit:
                if message.command == Command.READ:
                    payload_size = 1

                elif message.command == Command.WRITE:
                    payload_size = 1

                elif message.command == Command.IOCTL:
                    payload_size = 1

                elif message.command == Command.QUERY_DIRECTORY:
                    payload_size = 1

                else:
                    payload_size = 1

                credit_charge = (max(0, payload_size - 1) // 65536) + 1

            else:
                credit_charge = 0

            sequence_charge = max(1, credit_charge)
            for idx, window in enumerate(self.sequence_window):
                seq_id, num_creds = window

                if sequence_charge <= num_creds:
                    message_id = seq_id
                    credits_remaining = num_creds - sequence_charge
                    if credits_remaining:
                        self.sequence_window[idx] = (seq_id + sequence_charge, credits_remaining)
                    else:
                        del self.sequence_window[idx]

                    if not self.sequence_window:
                        # Used to trace the current high sequence window number for the response recharge
                        self.sequence_window.append((seq_id + sequence_charge, 0))

                    break

            else:
                raise Exception("Out of credits")

        session = self.session_table.get(session_id, None)
        if session and session.signing_required and not session.encrypt_data:
            flags |= HeaderFlags.SIGNED

        header = SMB2Header(
            credit_charge=credit_charge,
            channel_sequence=channel_sequence,
            status=0,
            command=message.command,
            credits=max(credits, credit_charge),
            flags=flags,
            next_command=next_command,
            message_id=message_id,
            async_id=0,
            tree_id=tree_id,
            session_id=session_id,
            signature=b"\x00" * 16,
        )
        self.outstanding_requests[message_id] = PendingRequest(message=message, receive_callback=callback)

        raw_data = bytearray(header.pack())
        raw_data += message.pack(len(raw_data))

        if flags & HeaderFlags.SIGNED:
            if self.signing_algorithm_id:
                raise NotImplementedError()

            elif self.dialect >= Dialect.SMB300:
                c = cmac.CMAC(algorithms.AES(session.signing_key), backend=default_backend())
                c.update(bytes(raw_data))
                signature = c.finalize()

            else:
                hmac_algo = hmac.new(session.signing_key, raw_data, digestmod=hashlib.sha256)
                signature = hmac_algo.digest()[:16]

            memoryview(raw_data)[48:64] = signature

        self._data_to_send += raw_data

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
        raw = memoryview(self._receive_buffer)
        if not raw:
            return None

        header, offset = unpack_header(raw)

        if isinstance(header, TransformHeader):
            raise Exception("FIXME decryption")

        elif isinstance(header, SMB1Header):
            if header.command != Command.SMB1_NEGOTIATE:
                raise Exception("Expecting SMB1 NEGOTIATE command")

            header = SMB2Header(
                credit_charge=0,
                channel_sequence=0,
                status=0,
                command=Command.NEGOTIATE,
                credits=1,
                flags=HeaderFlags.NONE,
                next_command=0,
                message_id=0,
                async_id=0,
                tree_id=0,
                session_id=0,
                signature=b"\x00" * 16,
            )
            self.sequence_window.append((1, 0))

        if not isinstance(header, SMB2Header):
            raise Exception("Unknown header this shouldn't occur ever")

        command = header.command
        next_command = header.next_command
        message_id = header.message_id
        granted_credits = header.credits
        self.sequence_window[-1] = (self.sequence_window[-1][0], self.sequence_window[-1][1] + granted_credits)

        message_cls = MESSAGES[command][1]
        message, message_offset = message_cls.unpack(self._receive_buffer, offset, offset)
        raw = raw[: offset + message_offset]

        if next_command:
            self._receive_buffer = self._receive_buffer[next_command:]
        else:
            # In case the message still contained padded bytes strip off the remaining NULL bytes.
            self._receive_buffer = self._receive_buffer[offset + message_offset :].lstrip(b"\x00")

        request = self.outstanding_requests[message_id]
        if request.receive_callback:
            new_event = request.receive_callback(header, message, raw)
            if new_event:
                return new_event

        if header.status == 0:
            return ResponseReceived(header, message)

        else:
            raise Exception(f"Received unknown status 0x{header.status:8X}")

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
            self._data_to_send += negotiate.pack(32)

            return

        self.client_security_mode = (
            SecurityModes.SIGNING_REQUIRED if self.config.require_message_signing else SecurityModes.SIGNING_ENABLED
        )

        if highest_dialect >= Dialect.SMB210:
            self.client_identifier = self.config.client_guid

        if highest_dialect >= Dialect.SMB300:
            self.client_capabilities = Capabilities.NONE

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

        msg = NegotiateRequest(
            dialects=self.offered_dialects,
            security_mode=self.client_security_mode,
            capabilities=self.client_capabilities,
            client_guid=self.client_identifier,
            negotiate_contexts=contexts,
        )
        self.create_header(msg, callback=self._process_negotiate)
        self.preauth_integrity_hash_value = bytes(self._data_to_send)

    def close(self) -> None:
        pass

    def _process_negotiate(
        self,
        header: SMB2Header,
        message: NegotiateResponse,
        raw: memoryview,
    ) -> None:
        self.max_transact_size = message.max_transact_size
        self.max_read_size = message.max_read_size
        self.max_write_size = message.max_write_size
        self.server_guid = message.server_guid
        self.gss_negotiate_token = message.security_buffer
        self.require_signing = bool(message.security_mode & SecurityModes.SIGNING_REQUIRED)

        if message.dialect_revision == Dialect.SMB2_WILDCARD:
            self.open(self.offered_dialects, as_smb1=False)
            return

        if message.dialect_revision not in self.offered_dialects:
            raise Exception("Received dialect we didn't ask for")

        self.dialect = message.dialect_revision
        if message.dialect_revision >= Dialect.SMB210:
            self.supports_file_leasing = bool(message.capabilities & Capabilities.LEASING)
            self.supports_multi_credit = bool(message.capabilities & Capabilities.LARGE_MTU)

        if message.dialect_revision >= Dialect.SMB300:
            self.supports_directory_leasing = bool(message.capabilities & Capabilities.DIRECTORY_LEASING)
            self.supports_multi_channel = bool(message.capabilities & Capabilities.MULTI_CHANNEL)

            if message.dialect_revision < Dialect.SMB311:
                self.supports_encryption = bool(message.capabilities & Capabilities.ENCRYPTION)

            self.server_capabilities = message.capabilities
            self.server_security_mode = message.security_mode

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
            pending_request = self.outstanding_requests[header.message_id]
            request = pending_request.message
            if not isinstance(request, NegotiateRequest):
                raise Exception("This shouln't happen")

            request_contexts: typing.Dict[ContextType, NegotiateContext] = {}
            for context in request.negotiate_contexts:
                request_contexts[context.context_type] = context

            found_contexts: typing.Set[ContextType] = set()
            for context in message.negotiate_contexts:
                if context.context_type in found_contexts:
                    raise Exception(f"Found multiple context {context.context_type}")
                found_contexts.add(context.context_type)

                if isinstance(context, PreauthIntegrityCapabilities):
                    if len(context.hash_algorithms) != 1:
                        raise Exception(f"Found {len(context.hash_algorithms)} algorithms, expecting 1")

                    algorithm_id = context.hash_algorithms[0]
                    request_preauth = typing.cast(
                        typing.Optional[PreauthIntegrityCapabilities], request_contexts.get(context.context_type, None)
                    )
                    if not request_preauth or algorithm_id not in request_preauth.hash_algorithms:
                        raise Exception("Unexpected pre auth hash algorithm selected")

                    hash_algo = next(
                        h for h in self.config.registered_hash_algorithms or [] if h.algorithm_id() == algorithm_id
                    )
                    self.preauth_integrity_hash_id = hash_algo()

                elif isinstance(context, EncryptionCapabilities):
                    if len(context.ciphers) != 1:
                        raise Exception(f"Found {len(context.ciphers)} ciphers, expecting 1")

                    if context.ciphers[0] != 0:
                        cipher_id = context.ciphers[0]
                        request_cipher = typing.cast(
                            typing.Optional[EncryptionCapabilities], request_contexts.get(context.context_type, None)
                        )
                        if not request_cipher or cipher_id not in request_cipher.ciphers:
                            raise Exception("Unexpected cipher selected")

                        cipher = next(c for c in self.config.registered_ciphers or [] if c.cipher_id() == cipher_id)
                        self.cipher_id = cipher()

            if not self.preauth_integrity_hash_id:
                raise Exception("Was expecting at least 1 preauth int cap")

            # The current value contains the full request - replace this with the hash value now the hash algorithm
            # has been negotiated.
            new_hash = self.preauth_integrity_hash_id.hash((b"\x00" * 64) + self.preauth_integrity_hash_value)
            self.preauth_integrity_hash_value = self.preauth_integrity_hash_id.hash(new_hash + bytes(raw))


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

            self.server_capabilities = message.capabilities
            self.server_identifier = message.client_guid

            if len(message.dialects) == 0:
                raise ValueError("Return STATUS_INVALID_PARAMETER")

            # FIXME: STATUS_NOT_SUPPORTED if no dialect match
            self.dialect = sorted(message.dialects, reverse=True)[0]

        nego_resp = NegotiateResponse(
            security_mode=self.client_security_mode,
            dialect_revision=self.dialect,
            server_guid=self.client_identifier,
            capabilities=self.client_capabilities,
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
            self.client_security_mode = SecurityModes.SIGNING_ENABLED
            if self.config.require_message_signing:
                self.client_security_mode = SecurityModes.SIGNING_REQUIRED

            self.client_identifier = self.config.identifier
            self.client_capabilities = Capabilities.NONE
            # FIXME: Add DFS capability based on config
            # FIXME: Set LEASING, LARGE_MTU if wildcard
            # FIXME: Max sizes should be 65536 if 2.0.2
            return False

        else:
            resp = SMB1NegotiateResponse(selected_index=-1)
            self.send_smb1(resp)
            return True
"""
