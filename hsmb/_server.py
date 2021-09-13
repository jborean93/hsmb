# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import datetime
import os
import typing
import uuid

from hsmb._config import SMBConfig, SMBRole, TransportIdentifier
from hsmb._events import Event, MessageReceived
from hsmb._exceptions import (
    ConnectionDisconnect,
    InvalidParameter,
    NotSupported,
    NtStatus,
    SmbNoPreauthIntegrityHashOverlap,
)
from hsmb._provider import (
    CompressionProvider,
    EncryptionProvider,
    HashingProvider,
    SigningProvider,
)
from hsmb.messages import (
    Capabilities,
    Cipher,
    Command,
    CompressionAlgorithm,
    CompressionCapabilities,
    CompressionCapabilityFlags,
    CompressionTransform,
    Dialect,
    EncryptionCapabilities,
    HeaderFlags,
    NegotiateContext,
    NegotiateContextType,
    NegotiateRequest,
    NegotiateResponse,
    PreauthIntegrityCapabilities,
    RdmaTransformCapabilities,
    SecurityModes,
    SigningAlgorithm,
    SigningCapabilities,
    SMB1Header,
    SMB2Header,
    SMBHeader,
    SMBMessage,
    TransformHeader,
    TransportCapabilities,
    TransportCapabilityFlags,
)


@dataclasses.dataclass
class ServerConfig(SMBConfig):
    """Global SMB server configuration.

    Global data that is required by the server. These fields are defined in
    `MS-SMB2 3.3.1.5 Global`_.

    Attributes:

    .. _MS-SMB2 3.3.1.5 Global:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/b3803e3b-e849-4827-a558-b2403deb24d9
    """

    role = SMBRole.SERVER

    # server_statistics
    # server_enabled
    share_list: typing.List = dataclasses.field(default_factory=list)
    global_open_table: typing.Dict[str, typing.Any] = dataclasses.field(default_factory=dict)
    global_session_table: typing.Dict[int, typing.Any] = dataclasses.field(default_factory=dict)
    connection_list: typing.Dict[str, typing.Any] = dataclasses.field(default_factory=dict)
    server_guid: uuid.UUID = dataclasses.field(default_factory=uuid.uuid4)
    server_start_time: datetime.datetime = dataclasses.field(default_factory=datetime.datetime.now)
    is_dfs_capable: bool = False
    # server_side_copy_max_number_of_chunks: int = 0
    # server_side_copy_max_data_size: int = 0
    # server_hash_level: ServerHashLevel = something
    global_lease_table_list: typing.Dict[str, typing.Any] = dataclasses.field(default_factory=dict)
    # max_resiliency_timeout: int = 0
    # resilient_open_scavenger_expiry_time: int = 0
    global_client_table: typing.Dict[uuid.UUID, typing.Any] = dataclasses.field(default_factory=dict)
    encrypt_data: bool = False
    reject_unencrypted_access: bool = False
    is_multi_channel_capable: bool = False
    allow_anonymous_access: bool = False
    is_shared_vhd_supported: bool = False
    max_cluster_dialect: Dialect = Dialect.SMB311
    supports_tree_connect_extn: bool = False
    allow_named_pipe_access_over_quic: bool = False


@dataclasses.dataclass
class ServerConnection:
    command_sequence_window: typing.List[typing.Tuple[int, int]] = dataclasses.field(default_factory=list)
    request_list: typing.Dict[int, "ServerRequest"] = dataclasses.field(default_factory=dict)
    client_capabilities: Capabilities = Capabilities.NONE
    negotiate_dialect: Dialect = Dialect.UNKNOWN
    async_command_list: typing.Dict[int, typing.Any] = dataclasses.field(default_factory=dict)
    dialect: str = "Unknown"
    should_sign: bool = False
    client_name: typing.Optional[str] = None
    max_transact_size: int = 65536
    max_write_size: int = 65536
    max_read_size: int = 65536
    supports_multi_credit: bool = False
    transport_name: TransportIdentifier = TransportIdentifier.UNKNOWN
    session_table: typing.Dict[int, typing.Any] = dataclasses.field(default_factory=dict)
    creation_time: int = 0
    preauth_session_table: typing.Dict[int, typing.Any] = dataclasses.field(default_factory=dict)
    # SMB 2.1
    client_guid: uuid.UUID = uuid.UUID(int=0)
    # SMB 3.x
    server_capabilities: Capabilities = Capabilities.NONE
    client_security_mode: SecurityModes = SecurityModes.NONE
    server_security_mode: SecurityModes = SecurityModes.NONE
    constrained_connection: bool = True
    # SMB 3.1.1
    preauth_integrity_hash_id: typing.Optional[HashingProvider] = None
    preauth_integrity_hash_value: bytes = b""
    cipher_id: typing.Optional[EncryptionProvider] = None
    client_dialects: typing.List[Dialect] = dataclasses.field(default_factory=list)
    compressor: typing.Optional[CompressionProvider] = None
    compression_ids: typing.List[CompressionAlgorithm] = dataclasses.field(default_factory=list)
    supports_chained_compression: bool = False
    rdma_transform_ids: typing.List[typing.Any] = dataclasses.field(default_factory=list)
    signing_algorithm_id: typing.Optional[SigningProvider] = None
    accept_transport_security: bool = False


@dataclasses.dataclass
class ServerRequest:
    message_id: int
    async_id: int = 0
    cancel_request_id: uuid.UUID = dataclasses.field(default_factory=uuid.uuid4)
    open: typing.Optional[typing.Any] = None
    # SMB 3.x
    is_encrypted: bool = False
    transform_session_id: int = 0
    # SMB 3.1.1
    compress_reply: bool = False


class SMBServer:
    def __init__(
        self,
        config: ServerConfig,
    ) -> None:
        self.config = config
        self.connection: ServerConnection = ServerConnection()
        self._data_to_send: typing.List[bytearray] = []
        self._receive_buffer: typing.List[bytearray] = []

    def send(
        self,
        message: SMBMessage,
        message_id: int,
        status: NtStatus = NtStatus.STATUS_SUCCESS,
        credit_response: int = 0,
        priority: typing.Optional[int] = None,
        session_id: int = 0,
        tree_id: int = 0,
        async_id: int = 0,
    ) -> None:
        if not self.connection:
            raise Exception("Cannot send any message without a negotiated connection")

        flags = HeaderFlags.SERVER_TO_REDIR
        if async_id:
            if tree_id:
                raise Exception("Cannot set both async_id and tree_id")

            flags |= HeaderFlags.ASYNC_COMMAND

        if priority is not None:
            if priority < 0 or priority > 7:
                raise ValueError("Priority must be between 0 and 7")
            flags |= priority << 4

        header = SMB2Header(
            credit_charge=0,
            channel_sequence=0,
            status=status,
            command=message.command,
            credits=credit_response,
            flags=flags,
            next_command=0,
            message_id=message_id,
            async_id=async_id,
            tree_id=tree_id,
            session_id=session_id,
            signature=b"\x00" * 16,
        )
        if status != NtStatus.STATUS_PENDING:
            del self.connection.request_list[message_id]

        data = header.pack()
        data += message.pack(len(data))
        self._data_to_send.append(data)

    def data_to_send(
        self,
    ) -> bytes:
        if self._data_to_send:
            return bytes(self._data_to_send.pop(0))
        else:
            return b""

    def receive_data(
        self,
        data: typing.Union[bytes, bytearray, memoryview],
    ) -> None:
        if data:
            self._receive_buffer.append(bytearray(data))

    def next_event(
        self,
    ) -> typing.Optional[Event]:
        if not self._receive_buffer:
            return None

        raw = self._receive_buffer.pop(0)
        receive_length = len(raw)
        view = memoryview(raw)
        header, offset = SMBHeader.unpack(view)
        transform_session_id = 0
        was_compressed = False

        if isinstance(header, SMB1Header):
            raise NotImplementedError()

        if isinstance(header, TransformHeader):
            raise NotImplementedError()

        if isinstance(header, CompressionTransform):
            was_compressed = True
            raise NotImplementedError()

        if not isinstance(header, SMB2Header):
            raise ConnectionDisconnect(f"Received unexpected SMB header sequence {type(header).__name__}")

        if header.command not in [Command.NEGOTIATE, Command.SMB1_NEGOTIATE] and self.connection.negotiate_dialect in [
            Dialect.UNKNOWN,
            Dialect.SMB2_WILDCARD,
        ]:
            raise ConnectionDisconnect("Expecting negotiate request before any other commands")

        if header.command != Command.CANCEL:
            request = ServerRequest(message_id=header.message_id)
            self.connection.request_list[header.message_id] = request
            if transform_session_id:
                request.is_encrypted = True
                request.transform_session_id = transform_session_id

            if was_compressed:
                request.compress_reply = True

            if receive_length > 65536 and (
                not self.connection.supports_multi_credit
                or header.command
                not in [
                    Command.READ,
                    Command.WRITE,
                    Command.IOCTL,
                    Command.QUERY_DIRECTORY,
                    Command.CHANGE_NOTIFY,
                    Command.QUERY_INFO,
                    Command.SET_INFO,
                ]
            ):
                raise ConnectionDisconnect("Received request that was too large")

        if header.command == Command.NEGOTIATE:
            return self._negotiate(header, view, offset)

        raise NotImplementedError()

    def _negotiate(
        self,
        header: SMB2Header,
        raw: memoryview,
        message_offset: int,
    ) -> Event:
        message = NegotiateRequest.unpack(raw, message_offset, message_offset)
        if self.connection.negotiate_dialect not in [Dialect.UNKNOWN, Dialect.SMB2_WILDCARD]:
            raise ConnectionDisconnect("Received negotiate request but dialect has already been negotiated")

        self.connection.client_capabilities = message.capabilities
        self.connection.client_security_mode = message.security_mode
        self.connection.client_guid = message.client_guid
        self.connection.should_sign = bool(message.security_mode & SecurityModes.SIGNING_REQUIRED)
        if len(message.dialects) == 0:
            raise InvalidParameter()

        dialect_map = {
            Dialect.SMB202: "2.0.2",
            Dialect.SMB210: "2.1",
            Dialect.SMB300: "3.0",
            Dialect.SMB302: "3.0.2",
            Dialect.SMB311: "3.1.1",
        }
        for d in sorted(message.dialects, reverse=True):
            if d in dialect_map:
                self.connection.dialect = dialect_map[d]
                self.connection.negotiate_dialect = d
                break

        else:
            raise NotSupported()

        self.connection.client_dialects = message.dialects

        response_contexts: typing.List[NegotiateContext] = []
        found_contexts: typing.Set[NegotiateContextType] = set()
        for context in message.negotiate_contexts:
            if self.connection.negotiate_dialect < Dialect.SMB311:
                continue

            if isinstance(context, PreauthIntegrityCapabilities):
                if context.context_type in found_contexts:
                    raise InvalidParameter()
                found_contexts.add(context.context_type)

                available_hash_algos = {h.algorithm_id: h for h in self.config.registered_hash_algorithms or []}
                for h in context.hash_algorithms:
                    if h in available_hash_algos:
                        self.connection.preauth_integrity_hash_id = available_hash_algos[h]
                        break

                if not self.connection.preauth_integrity_hash_id:
                    raise SmbNoPreauthIntegrityHashOverlap()

                self.connection.preauth_integrity_hash_value = self.connection.preauth_integrity_hash_id.hash(
                    b"\x00" * 64 + bytes(raw)
                )
                response_contexts.append(
                    PreauthIntegrityCapabilities(
                        hash_algorithms=[self.connection.preauth_integrity_hash_id.algorithm_id],
                        salt=os.urandom(32),
                    )
                )

            elif isinstance(context, EncryptionCapabilities):
                if context.context_type in found_contexts:
                    raise InvalidParameter()
                found_contexts.add(context.context_type)

                available_ciphers = {c.cipher_id: c for c in self.config.registered_ciphers or []}
                return_ciphers: typing.List[Cipher] = []
                for c in context.ciphers:
                    if c in available_ciphers:
                        self.connection.cipher_id = available_ciphers[c]
                        return_ciphers.append(c)
                        break

                else:
                    return_ciphers.append(Cipher.NONE)

                response_contexts.append(EncryptionCapabilities(ciphers=return_ciphers))

            elif isinstance(context, CompressionCapabilities):
                if context.context_type in found_contexts:
                    raise InvalidParameter()
                found_contexts.add(context.context_type)

                if not self.config.is_compression_supported:
                    continue

                if len(context.compression_algorithms) == 0:
                    raise InvalidParameter()

                can_chain = False
                available_compressors: set[CompressionAlgorithm] = set()
                if self.config.registered_compressor:
                    available_compressors = set(self.config.registered_compressor.compression_ids)
                    can_chain = self.config.registered_compressor.can_chain
                    self.connection.compressor = self.config.registered_compressor
                    available_compressors.intersection_update(set(context.compression_algorithms))

                self.connection.compression_ids = list(available_compressors)
                flags = CompressionCapabilityFlags.NONE
                if (
                    context.flags & CompressionCapabilityFlags.CHAINED
                    and self.config.is_chained_compression_supported
                    and can_chain
                ):
                    self.connection.supports_chained_compression = True
                    flags |= CompressionCapabilityFlags.CHAINED

                response_contexts.append(
                    CompressionCapabilities(
                        flags=flags,
                        compression_algorithms=self.connection.compression_ids,
                    )
                )

            elif isinstance(context, RdmaTransformCapabilities):
                if context.context_type in found_contexts:
                    raise InvalidParameter()
                found_contexts.add(context.context_type)

                raise NotImplementedError()

            elif isinstance(context, SigningCapabilities):
                if context.context_type in found_contexts:
                    raise InvalidParameter()
                found_contexts.add(context.context_type)

                if len(context.signing_algorithms) == 0:
                    raise InvalidParameter()

                available_sign_algos = {s.signing_id: s for s in self.config.registered_signing_algorithms or []}
                for s in context.signing_algorithms:
                    if s in available_sign_algos:
                        self.connection.signing_algorithm_id = available_sign_algos[s]
                        response_contexts.append(SigningCapabilities(signing_algorithms=[s]))
                        break

                # If nothing was negotiated the context isn't returned and the SMB 3 default of AES CMAC is used.

            elif isinstance(context, TransportCapabilities):
                if context.context_type in found_contexts:
                    raise InvalidParameter()
                found_contexts.add(context.context_type)

                if (
                    self.connection.transport_name == TransportIdentifier.QUIC
                    and self.config.disable_encryption_over_secure_transport
                    and context.flags & TransportCapabilityFlags.ACCEPT_TRANSPORT_LEVEL_SECURITY
                ):
                    self.connection.accept_transport_security = True

                transport_flags = TransportCapabilityFlags.NONE
                if self.connection.accept_transport_security:
                    transport_flags |= TransportCapabilityFlags.ACCEPT_TRANSPORT_LEVEL_SECURITY
                response_contexts.append(TransportCapabilities(flags=transport_flags))

        if self.connection.negotiate_dialect >= Dialect.SMB210 and self.connection.transport_name in [
            TransportIdentifier.UNKNOWN,
            TransportIdentifier.DIRECT_TCP,
        ]:
            self.connection.supports_multi_credit = True

        security_mode = SecurityModes.SIGNING_ENABLED
        if self.config.require_message_signing:
            security_mode |= SecurityModes.SIGNING_REQUIRED

        capabilities = Capabilities.NONE
        # capabilities |= Capabilities.DFS
        # capabilities |= Capabilities.LEASING
        if self.connection.supports_multi_credit:
            capabilities |= Capabilities.LARGE_MTU

        if self.connection.negotiate_dialect >= Dialect.SMB300:
            capabilities |= Capabilities.DIRECTORY_LEASING
            capabilities |= Capabilities.PERSISTENT_HANDLES

            if self.config.is_multi_channel_capable:
                capabilities |= Capabilities.MULTI_CHANNEL

            if self.config.is_encryption_supported:
                # FIXME: Handle 0 for SMB 3.1.1
                capabilities |= Capabilities.ENCRYPTION

            self.connection.server_security_mode = security_mode
            self.connection.server_capabilities = capabilities

        # FIXME
        self.connection.max_transact_size = 65536
        self.connection.max_write_size = 65536
        self.connection.max_read_size = 65536

        response = NegotiateResponse(
            security_mode=security_mode,
            dialect_revision=self.connection.negotiate_dialect,
            server_guid=self.config.server_guid,
            capabilities=capabilities,
            max_transact_size=self.connection.max_transact_size,
            max_read_size=self.connection.max_read_size,
            max_write_size=self.connection.max_write_size,
            system_time=0,  # FIXME
            server_start_time=0,
            security_buffer=None,  # FIXME
            negotiate_contexts=response_contexts,
        )
        self.send(response, header.message_id, credit_response=1)

        if self.connection.preauth_integrity_hash_id:
            self.connection.preauth_integrity_hash_value = self.connection.preauth_integrity_hash_id.hash(
                self.connection.preauth_integrity_hash_value + bytes(self._data_to_send[0])
            )

        return MessageReceived(header, message, data_available=True)
