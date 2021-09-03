# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import contextlib
import dataclasses
import datetime
import os
import struct
import typing
import uuid

from hsmb._config import SMBConfig, SMBRole, TransportIdentifier
from hsmb._create import (
    CloseFlags,
    CloseRequest,
    CloseResponse,
    CreateDisposition,
    CreateOptions,
    CreateRequest,
    CreateResponse,
    ImpersonationLevel,
    RequestedOplockLevel,
    ShareAccess,
)
from hsmb._crypto import (
    AES128CCMCipher,
    AESCMACSigningAlgorithm,
    HMACSHA256SigningAlgorithm,
    smb3kdf,
)
from hsmb._events import (
    ErrorReceived,
    Event,
    FileOpened,
    MessageReceived,
    ProtocolNegotiated,
    SessionAuthenticated,
    SessionProcessingRequired,
    TreeConnected,
)
from hsmb._exceptions import NtStatus, unpack_error_response
from hsmb._io import (
    FlushRequest,
    FlushResponse,
    ReadChannel,
    ReadRequest,
    ReadRequestFlags,
    ReadResponse,
    WriteChannel,
    WriteFlags,
    WriteRequest,
    WriteResponse,
)
from hsmb._ioctl import (
    IOCTLRequest,
    IOCTLResponse,
    ValidateNegotiateInfoRequest,
    ValidateNegotiateInfoResponse,
)
from hsmb._messages import (
    Command,
    HeaderFlags,
    SMB1Header,
    SMB1HeaderFlags,
    SMB2Header,
    SMBHeader,
    SMBMessage,
    TransformHeader,
    unpack_header,
)
from hsmb._negotiate import (
    Capabilities,
    Cipher,
    CipherBase,
    CompressionAlgorithm,
    CompressionAlgorithmBase,
    CompressionCapabilities,
    CompressionCapabilityFlags,
    ContextType,
    Dialect,
    EncryptionCapabilities,
    HashAlgorithm,
    HashAlgorithmBase,
    NegotiateContext,
    NegotiateRequest,
    NegotiateResponse,
    NetnameNegotiate,
    PreauthIntegrityCapabilities,
    RdmaTransformCapabilities,
    RdmaTransformId,
    SecurityModes,
    SigningAlgorithm,
    SigningAlgorithmBase,
    SigningCapabilities,
    SMB1NegotiateRequest,
    SMB1NegotiateResponse,
    TransportCapabilities,
    TransportCapabilityFlags,
)
from hsmb._session import (
    LogoffRequest,
    LogoffResponse,
    SessionFlags,
    SessionSetupFlags,
    SessionSetupRequest,
    SessionSetupResponse,
)
from hsmb._tree import (
    ShareCapabilities,
    ShareFlags,
    ShareType,
    TreeConnectFlags,
    TreeConnectRequest,
    TreeConnectResponse,
    TreeContext,
    TreeDisconnectRequest,
    TreeDisconnectResponse,
)

try:
    from typing import Protocol
except ImportError:
    # Python < 3.8
    from typing_extensions import Protocol  # type: ignore[misc]


class ClientResponseCallback(Protocol):
    def __call__(
        self,
        __header: SMB2Header,
        __raw: memoryview,
        __message_offset: int,
        __state: typing.Dict[str, typing.Any],
    ) -> Event:
        ...


@dataclasses.dataclass
class ClientConfig(SMBConfig):
    """Global SMB client configuration.

    Global data that is required by the client. These fields are defined in
    `MS-SMB2 3.2.1.1 Global`_.

    Attributes:
        connection_table: Active SMB2 connections, indexed by the server name.
        global_file_table: All opened fields, indexed by name.
        client_guid: A global identifier for this client.
        max_dialect: The highest SMB2 dialect that the client implements.
        require_secure_negotiate: Client requires validation of the negotiation
            phase.
        server_list: A dict of server entries, indexed by the server name.
        share_list: A dict of server shares, indexed by the share path.
        compress_all_requests: Empowers the client to compress all requests.

    .. _MS-SMB2 3.2.1.1 Global:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/89f8c694-cbc9-47fb-9996-d7ec35106dc4
    """

    role = SMBRole.CLIENT

    connection_table: typing.Dict[str, "ClientConnection"] = dataclasses.field(default_factory=dict)
    global_file_table: typing.Dict[str, typing.Any] = dataclasses.field(default_factory=dict)
    client_guid: uuid.UUID = dataclasses.field(default_factory=uuid.uuid4)
    max_dialect: Dialect = Dialect.SMB311
    require_secure_negotiate: bool = True
    server_list: typing.Dict[str, "ClientServer"] = dataclasses.field(default_factory=dict)
    share_list: typing.Dict[str, "ClientShare"] = dataclasses.field(default_factory=dict)
    compress_all_requests: bool = False


@dataclasses.dataclass
class ClientConnection:
    session_table: typing.Dict[int, "ClientSession"] = dataclasses.field(default_factory=dict)
    preauth_session_table: typing.Dict[int, "ClientSession"] = dataclasses.field(default_factory=dict)
    outstanding_requests: typing.Dict[int, "ClientPendingRequest"] = dataclasses.field(default_factory=dict)
    sequence_window: typing.List[typing.Tuple[int, int]] = dataclasses.field(default_factory=list)
    gss_negotiate_token: typing.Optional[bytes] = None
    max_transact_size: int = 65536
    max_read_size: int = 65536
    max_write_size: int = 65536
    server_guid: uuid.UUID = uuid.UUID(int=0)
    require_signing: bool = False
    server_name: typing.Optional[str] = None
    # SMB 2.1
    dialect: Dialect = Dialect.UNKNOWN
    supports_file_leasing: bool = False
    supports_multi_credit: bool = False
    client_guid: uuid.UUID = uuid.UUID(int=0)
    # SMB 3.x
    supports_directory_leasing: bool = False
    supports_multi_channel: bool = False
    supports_persistent_handles: bool = False
    supports_encryption: bool = False
    client_capabilities: Capabilities = Capabilities.NONE
    server_capabilities: Capabilities = Capabilities.NONE
    client_security_mode: SecurityModes = SecurityModes.NONE
    server_security_mode: SecurityModes = SecurityModes.NONE
    server: typing.Optional["ClientServer"] = None
    offered_dialects: typing.List[Dialect] = dataclasses.field(default_factory=list)
    # SMB 3.1.1
    preauth_integrity_hash_id: typing.Optional[HashAlgorithmBase] = None
    preauth_integrity_hash_value: bytes = b""
    cipher_id: typing.Optional[CipherBase] = None
    compression_ids: typing.List[CompressionAlgorithmBase] = dataclasses.field(default_factory=list)
    supports_chained_compression: bool = False
    rdma_transform_ids: typing.List[typing.Any] = dataclasses.field(default_factory=list)
    signing_algorithm_id: typing.Optional[SigningAlgorithmBase] = None
    accept_transport_security: bool = True


@dataclasses.dataclass
class ClientSession:
    connection: ClientConnection
    session_id: int
    tree_connect_table: typing.Dict[int, "ClientTreeConnect"] = dataclasses.field(default_factory=dict)
    session_key: bytes = b""
    signing_required: bool = False
    open_table: typing.Dict[bytes, "ClientApplicationOpenFile"] = dataclasses.field(default_factory=dict)
    is_anonymous: bool = False
    is_guest: bool = False
    channel_list: typing.Dict[int, "ClientChannel"] = dataclasses.field(default_factory=dict)
    channel_sequence: int = 0
    encrypt_data: bool = False
    encryption_key: bytes = b""
    decryption_key: bytes = b""
    signing_key: bytes = b""
    application_key: bytes = b""
    preauth_integrity_hash_value: bytes = b""
    full_session_key: bytes = b""


@dataclasses.dataclass
class ClientTreeConnect:
    share_name: str
    tree_connect_id: int
    session: ClientSession
    is_dfs_share: bool = False
    is_ca_share: bool = False
    encrypt_data: bool = False
    is_scaleout_share: bool = False
    compress_data: bool = False
    share_type: ShareType = ShareType.UNKNOWN


@dataclasses.dataclass
class ClientOpenFile:
    open_table: typing.Dict = dataclasses.field(default_factory=dict)
    lease_key: bytes = b""
    lease_state: typing.Any = None
    lease_epoch: int = 0


@dataclasses.dataclass
class ClientApplicationOpenFile:
    file_id: bytes
    tree_connect: ClientTreeConnect
    connection: ClientConnection
    session: ClientSession
    oplock_level: int
    durable: bool
    file_name: str
    resiliant_handle: bool
    last_disconnect_time: int
    resilient_timeout: int
    operation_bucket: typing.List
    desired_access: int
    share_mode: ShareAccess
    create_options: CreateOptions
    file_attributes: int
    create_disposition: CreateDisposition
    durable_timeout: int
    outstanding_requests: typing.Dict
    create_guid: uuid.UUID
    is_persistent: bool


@dataclasses.dataclass
class ClientPendingRequest:
    # Custom used by hsmb
    message_id: int
    receive_callback: ClientResponseCallback
    receive_callback_state: typing.Dict[str, typing.Any]

    # Part of MS-SMB2
    message: bytes
    async_id: int = 0
    cancel_id: uuid.UUID = dataclasses.field(default_factory=uuid.uuid4)
    timestamp: datetime.datetime = dataclasses.field(default_factory=datetime.datetime.now)
    buffer_descriptor_list: typing.List = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class ClientChannel:
    signing_key: bytes
    connection: ClientConnection


@dataclasses.dataclass
class ClientServer:
    """Client Server config.

    Server metadata used by a client connection. These fields are defined in
    `MS-SMB2 3.2.1.9 Per Server`_. The configuration is generated by the client
    connection after receiving the :class:hsmb.NegotiateResponse` message.

    Attributes:
        server_guid: A globally unique identifier (GUID) that is generated by
            the remote server to uniquely identify the remote server.
        dialect_revision: Preferred dialect between client and server.
        capabilities: The capabilities received from the server in the
            :class:`hsmb.NegotiateResponse`.
        security_mode: The security mode received from the server in the
            :class:`hsmb.NegotiateResponse`.
        address_list: A list of IPv4 and IPv6 addresses hosted on the server.
        server_name: The fully qualified domain name, NetBIOS name, or an IP
            address of the server machine.
        cipher_id: The negotiated cipher algorithms between the client and
            server - Dialect 3.1.1 or newer.
        rdma_transform_ids: A list of RDMA transform identifiers, if any,
            negotiated between client and server.
        signing_algorithm_id: An identifier of the signing algorithm, if any,
            negotiated between client and server.

    .. _MS-SMB2 3.2.1.9 Per Server:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/f388d7e0-9bc3-4d9c-98e5-71f8e36b3c4f
    """

    server_guid: uuid.UUID
    dialect_revision: Dialect
    capabilities: Capabilities
    security_mode: SecurityModes
    address_list: typing.List[str]
    server_name: str
    cipher_id: typing.Optional[CipherBase] = None
    # SMB 3.1.1
    rdma_transform_ids: typing.List[RdmaTransformId] = dataclasses.field(default_factory=list)
    signing_algorithm_id: typing.Optional[SigningAlgorithmBase] = None


@dataclasses.dataclass
class ClientShare:
    """Client share config.

    Share metadata used by a client connection. These fields are defined in
    `MS-SMB2 3.2.1.10 Per Share`_. The configuration is generated by the client
    connection after receiving the FIXME type message.

    Attributes:
        path_name: A path that describes the resource that is being shared.
        encrypt_data: Indicates that the server requires messages for accessing
            this share to be encrypted.

    .. _MS-SMB2 3.2.1.10 Per Share:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/9158b3b4-78d3-499d-894d-8ede81091e82
    """

    path_name: str
    encrypt_data: bool
    share_type: ShareType = ShareType.UNKNOWN


class SMBClient:
    def __init__(
        self,
        config: ClientConfig,
    ) -> None:
        self.config = config
        self.connection: typing.Optional[ClientConnection] = None
        self._data_to_send: typing.List[typing.Union[bytearray, memoryview]] = []
        self._receive_buffer: typing.List[bytearray] = []
        self._transaction: typing.Optional[typing.List[typing.Tuple[SMB2Header, SMBMessage]]] = None

    @contextlib.contextmanager
    def transaction(
        self,
        related: bool = False,
    ) -> typing.Iterator[typing.List[typing.Tuple[SMB2Header, SMBMessage]]]:
        if not self.connection:
            raise Exception("Connection has not been negotiated")

        if self._transaction:
            nested_transaction = True
            transaction = self._transaction
        else:
            nested_transaction = False
            transaction = []

        try:
            yield transaction

        finally:
            if nested_transaction or not transaction:
                return

            self._transaction = None
            must_encrypt = False
            must_compress = False
            all_session: typing.Optional[ClientSession] = None
            raw_messages: typing.List[typing.Tuple[SMB2Header, memoryview]] = []

            for idx, payload in enumerate(transaction):
                header, message = payload

                session = self.connection.session_table.get(header.session_id, None)
                if session and session.encrypt_data:
                    must_encrypt = True

                    if not all_session:
                        all_session = session

                    if all_session.session_id != session.session_id:
                        raise Exception("Cannot encrypt compound message with different sessions")

                data = header.pack()
                data += message.pack(len(data))

                # If this is not the last message add padding to ensure each header is aligned to the 8 byte boundary.
                if idx != len(transaction) - 1:
                    padding_size = 8 - (len(data) % 8 or 8)
                    data += b"\x00" * padding_size

                    # The next_command value cannot be known until after the header is built so just adjust it
                    struct.pack("<I", memoryview(data)[20:24], len(data))

                if header.flags & HeaderFlags.SIGNED:
                    if not self.connection.signing_algorithm_id:
                        raise Exception("No signer available to sign message")

                    if not session:
                        raise Exception("Cannot sign without session")

                    signature = self.connection.signing_algorithm_id.sign(session.signing_key, header, bytes(data))
                    memoryview(data)[48:64] = signature

                request = self.connection.outstanding_requests[header.message_id]
                request.message = bytes(data)
                raw_messages.append((header, memoryview(request.message)))

            if len(raw_messages) == 1 and not must_encrypt and not must_compress:
                # Avoid creating yet another buffer and just append the memoryview
                self._data_to_send.append(raw_messages[0][1])
                return

            buffer = bytearray()
            if must_encrypt:
                if not self.connection.cipher_id:
                    raise Exception("No cipher available to encrypt")

                if not all_session:
                    raise Exception("No session available to encrypt")

                for header, msg in raw_messages:
                    enc_data = self.connection.cipher_id.encrypt(all_session.encryption_key, header, bytes(msg))
                    buffer += enc_data

            if must_compress:
                raise NotImplementedError()

            self._data_to_send.append(buffer)

    def send(
        self,
        message: SMBMessage,
        callback: ClientResponseCallback,
        callback_state: typing.Dict[str, typing.Any],
        channel_sequence: int = 0,
        credits: int = 0,
        priority: typing.Optional[int] = None,
        session_id: int = 0,
        tree_id: int = 0,
        related: bool = False,
        must_sign: bool = False,
    ) -> ClientPendingRequest:
        if not self.connection:
            raise Exception("Cannot send any message without a negotiated connection")

        # This is a no-op if we are already in a transaction - otherwise it adds the message to the queue.
        with self.transaction() as queue:
            flags = HeaderFlags.NONE
            if priority is not None:
                if priority < 0 or priority > 7:
                    raise ValueError("Priority must be between 0 and 7")
                flags |= priority << 4

            if related and queue:
                first_session_id = queue[0][0].session_id
                first_tree_id = queue[0][0].tree_id
                if session_id != first_session_id:
                    raise Exception("Cannot send related header with different session ids")

                if tree_id != first_tree_id:
                    raise Exception("Cannot send related header with different tree ids")

                flags = HeaderFlags.RELATED_OPERATIONS
                header_session_id = 0xFFFFFFFFFFFFFFFF
                header_tree_id = 0xFFFFFFFF

            else:
                header_session_id = session_id
                header_tree_id = tree_id

            credit_charge: int
            message_id: int
            if message.command == Command.CANCEL:
                # FIXME: This should be the id of the request being cancelled
                message_id = 0
                credit_charge = 0

            else:
                if self.connection.supports_multi_credit:
                    if isinstance(message, ReadRequest):
                        payload_size = message.length + len(message.read_channel_info or b"")

                    elif isinstance(message, WriteRequest):
                        payload_size = len(message.data) + len(message.write_channel_info or b"")

                    elif isinstance(message, IOCTLRequest):
                        send_size = len(message.input) + len(message.output)
                        recv_size = message.max_input_response + message.max_output_response
                        payload_size = max(send_size, recv_size)

                    elif message.command == Command.QUERY_DIRECTORY:
                        raise NotImplementedError()

                    else:
                        payload_size = 1

                    credit_charge = (max(0, payload_size - 1) // 65536) + 1

                else:
                    credit_charge = 0

                sequence_charge = max(1, credit_charge)
                for idx, window in enumerate(self.connection.sequence_window):
                    seq_id, num_creds = window

                    if sequence_charge <= num_creds:
                        message_id = seq_id
                        credits_remaining = num_creds - sequence_charge
                        if credits_remaining:
                            self.connection.sequence_window[idx] = (seq_id + sequence_charge, credits_remaining)
                        else:
                            del self.connection.sequence_window[idx]

                        if not self.connection.sequence_window:
                            # Used to trace the current high sequence window number for the response recharge
                            self.connection.sequence_window.append((seq_id + sequence_charge, 0))

                        break

                else:
                    raise Exception("Out of credits")

            session = self.connection.session_table.get(session_id, None)
            if must_sign or (session and session.signing_required and not session.encrypt_data):
                flags |= HeaderFlags.SIGNED

            header = SMB2Header(
                credit_charge=credit_charge,
                channel_sequence=channel_sequence,
                status=0,
                command=message.command,
                credits=max(credits, credit_charge),
                flags=flags,
                next_command=0,
                message_id=message_id,
                async_id=0,
                tree_id=header_tree_id,
                session_id=header_session_id,
                signature=b"\x00" * 16,
            )

            queue.append((header, message))
            self.connection.outstanding_requests[message_id] = req = ClientPendingRequest(
                message_id=message_id,
                receive_callback=callback,
                receive_callback_state=callback_state,
                message=b"",  # Set by the transaction when it's packed and signed
            )

            return req

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
        self._receive_buffer.append(bytearray(data))

    def next_event(
        self,
    ) -> typing.Optional[Event]:
        if not self.connection:
            raise Exception("Cannot process any events until a connection is created")

        if not self._receive_buffer:
            return None

        raw = memoryview(self._receive_buffer[0])
        header, offset = unpack_header(raw)

        if isinstance(header, TransformHeader):
            if not self.connection.cipher_id:
                raise Exception("Received encrypted message but no cipher was available for decryption")

            session = self.connection.session_table[header.session_id]
            decrypted_data = self.connection.cipher_id.decrypt(session.decryption_key, header, bytes(raw))
            del self._receive_buffer[0]
            self._receive_buffer.insert(0, bytearray(decrypted_data))
            raw = memoryview(decrypted_data)
            header, offset = unpack_header(raw)

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
            self.connection.sequence_window.append((1, 0))

        if not isinstance(header, SMB2Header):
            raise Exception("Unknown header this shouldn't occur ever")

        next_command = header.next_command
        message_id = header.message_id
        granted_credits = header.credits
        self.connection.sequence_window[-1] = (
            self.connection.sequence_window[-1][0],
            self.connection.sequence_window[-1][1] + granted_credits,
        )

        request = self.connection.outstanding_requests[message_id]
        try:
            return request.receive_callback(header, raw, offset, request.receive_callback_state)
        finally:
            del self.connection.outstanding_requests[message_id]

            if next_command:
                self._receive_buffer[0] = self._receive_buffer[0][next_command:]
            else:
                del self._receive_buffer[0]

    def negotiate(
        self,
        server_name: str,
        offered_dialects: typing.Optional[typing.List[Dialect]] = None,
        transport_identifier: TransportIdentifier = TransportIdentifier.UNKNOWN,
    ) -> ClientPendingRequest:
        if self.connection:
            raise Exception("Connection has already been negotiated")

        if offered_dialects:
            requested_dialects = offered_dialects
        else:
            requested_dialects = [
                d for d in Dialect if d not in [Dialect.UNKNOWN, Dialect.SMB2_WILDCARD] and d <= self.config.max_dialect
            ]
        highest_dialect = sorted(requested_dialects, reverse=True)[0]

        client_security_mode = (
            SecurityModes.SIGNING_REQUIRED if self.config.require_message_signing else SecurityModes.SIGNING_ENABLED
        )

        client_guid = uuid.UUID(int=0)
        if highest_dialect >= Dialect.SMB210:
            client_guid = self.config.client_guid

        client_capabilities = Capabilities.NONE
        if highest_dialect >= Dialect.SMB300:
            client_capabilities = Capabilities.NONE

        self.config.connection_table[server_name] = self.connection = connection = ClientConnection(
            sequence_window=[(0, 1)],
            server_name=server_name,
            client_guid=client_guid,
            client_capabilities=client_capabilities,
            client_security_mode=client_security_mode,
            offered_dialects=requested_dialects,
        )

        # if as_smb1:
        #     smb1_dialects = ["SMB 2.???"]
        #     if Dialect.SMB202 in offered_dialects:
        #         smb1_dialects.insert(0, "SMB 2.002")

        #     negotiate = SMB1NegotiateRequest(dialects=smb1_dialects)

        #     flags = SMB1HeaderFlags.EAS | SMB1HeaderFlags.NT_STATUS | SMB1HeaderFlags.UNICODE
        #     header = SMB1Header(command=negotiate.command.value, status=0, flags=flags, pid=0, tid=0, uid=0, mid=0)
        #     self._data_to_send += header.pack()
        #     self._data_to_send += negotiate.pack(32)

        #     return

        contexts: typing.List[NegotiateContext] = []
        requested_preauth_algos = {h.algorithm_id(): h for h in self.config.registered_hash_algorithms or []}
        requested_ciphers = {c.cipher_id(): c for c in self.config.registered_ciphers or []}
        requested_compressors = {c.compression_id(): c for c in self.config.registered_compressors or []}
        requested_signers = {s.signing_id(): s for s in self.config.registered_signing_algorithms or []}

        if highest_dialect >= Dialect.SMB311:
            if not requested_preauth_algos:
                raise Exception("No registered hash algorithms available")

            contexts.append(
                PreauthIntegrityCapabilities(
                    hash_algorithms=list(requested_preauth_algos.keys()),
                    salt=os.urandom(32),
                ),
            )

            if self.config.is_encryption_supported and requested_ciphers:
                contexts.append(EncryptionCapabilities(ciphers=list(requested_ciphers.keys())))

            if self.config.is_compression_supported and requested_compressors:
                contexts.append(
                    CompressionCapabilities(
                        flags=CompressionCapabilityFlags.NONE,
                        compression_algorithms=list(requested_compressors.keys()),
                    )
                )

            # FIXME: Set based on the config values
            if False and self.config.is_rdma_transform_supported:
                contexts.append(RdmaTransformCapabilities(rdma_transform_ids=[RdmaTransformId.NONE]))

            contexts.append(NetnameNegotiate(net_name=server_name))

            if requested_signers:
                contexts.append(SigningCapabilities(signing_algorithms=list(requested_signers.keys())))

            if (
                transport_identifier == TransportIdentifier.QUIC
                and not self.config.disable_encryption_over_secure_transport
            ):
                contexts.append(TransportCapabilities(flags=TransportCapabilityFlags.ACCEPT_TRANSPORT_LEVEL_SECURITY))

        msg = NegotiateRequest(
            dialects=requested_dialects,
            security_mode=client_security_mode,
            capabilities=client_capabilities,
            client_guid=client_guid or uuid.UUID(int=0),
            negotiate_contexts=contexts,
        )

        callback_state = {
            "client": self,
            "config": self.config,
            "connection": connection,
            "server_name": server_name,
            "transport_identifier": transport_identifier,
            "requested_dialects": requested_dialects,
            "requested_preauth_algos": requested_preauth_algos,
            "requested_ciphers": requested_ciphers,
            "requested_compressors": requested_compressors,
            "requested_signers": requested_signers,
        }
        request = self.send(msg, callback=_process_negotiate_response, callback_state=callback_state)

        return request

    def session_setup(
        self,
        security_buffer: bytes,
        session_id: int = 0,
        previous_session_id: int = 0,
    ) -> ClientPendingRequest:
        if not self.connection:
            raise Exception("No connection has been negotiated")

        if session_id:
            session = self.connection.preauth_session_table[session_id]
        else:
            session = ClientSession(
                connection=self.connection,
                session_id=0,
            )

        security_mode = (
            SecurityModes.SIGNING_REQUIRED if self.config.require_message_signing else SecurityModes.SIGNING_ENABLED
        )

        request = self.send(
            SessionSetupRequest(
                flags=SessionSetupFlags.NONE,
                security_mode=security_mode,
                capabilities=Capabilities.DFS,
                channel=0,
                previous_session_id=previous_session_id,
                security_buffer=security_buffer,
            ),
            session_id=session.session_id,
            callback=_process_session_setup_response,
            callback_state={"session": session},
        )

        if self.connection.preauth_integrity_hash_id:
            pre_hash = session.preauth_integrity_hash_value or self.connection.preauth_integrity_hash_value
            session.preauth_integrity_hash_value = self.connection.preauth_integrity_hash_id.hash(
                pre_hash + request.message
            )

        return request

    def set_session_key(
        self,
        key: bytes,
        event: SessionAuthenticated,
    ) -> None:
        if not self.connection:
            raise Exception("No connection has been negotiated")

        if event.session_id not in self.connection.preauth_session_table:
            raise Exception("Failed to find preauthenticated session waiting for session key")

        if self.connection.dialect >= Dialect.SMB311 and not event.header.flags & HeaderFlags.SIGNED:
            raise Exception("SessionSetup Response must be signed when using SMB 3.1.1")

        event.session.full_session_key = key
        event.session.session_key = key[:16].ljust(16, b"\x00")

        if self.connection.dialect >= Dialect.SMB311:
            context = event.session.preauth_integrity_hash_value
            event.session.signing_key = smb3kdf(event.session.session_key, b"SMBSigningKey\x00", context)
            event.session.application_key = smb3kdf(event.session.session_key, b"SMBAppKey\x00", context)

            key = event.session.session_key
            length = 16

            if self.connection.cipher_id and self.connection.cipher_id.cipher_id() in [
                Cipher.AES256_CCM,
                Cipher.AES256_GCM,
            ]:
                key = event.session.full_session_key
                length = 32

            event.session.encryption_key = smb3kdf(key, b"SMBC2SCipherKey\x00", context, length=length)
            event.session.decryption_key = smb3kdf(key, b"SMBS2CCipherKey\x00", context, length=length)

        elif self.connection.dialect >= Dialect.SMB300:
            event.session.signing_key = smb3kdf(event.session.session_key, b"SMB2AESCMAC\x00", b"SmbSign\x00")
            event.session.application_key = smb3kdf(event.session.session_key, b"SMB2APP\x00", b"SmbRpc\x00")
            event.session.encryption_key = smb3kdf(event.session.session_key, b"SMB2AESCCM\x00", b"ServerIn \x00")
            event.session.decryption_key = smb3kdf(event.session.session_key, b"SMB2AESCCM\x00", b"ServerOut\x00")

        else:
            event.session.signing_key = event.session.session_key
            event.session.application_key = event.session.session_key

        event.session.signing_required = self.config.require_message_signing or self.connection.require_signing
        if event.message.session_flags & SessionFlags.ENCRYPT_DATA:
            event.session.signing_required = False
            event.session.encrypt_data = True

        if event.header.flags & HeaderFlags.SIGNED:
            if not self.connection.signing_algorithm_id:
                raise Exception("No signing algorithm set up")

            expected_signature = event.header.signature
            raw_data = bytearray(event.raw_data)
            memoryview(raw_data)[48:64] = b"\x00" * 16

            actual_signature = self.connection.signing_algorithm_id.sign(
                event.session.signing_key, event.header, bytes(raw_data)
            )
            if actual_signature != expected_signature:
                raise Exception("Signature mismatch")

        self.connection.session_table[event.session_id] = self.connection.preauth_session_table.pop(event.session_id)

    def logoff(
        self,
        session_id: int,
    ) -> ClientPendingRequest:
        if not self.connection:
            raise Exception("No connection has been negotiated")

        session = self.connection.session_table.get(session_id, None)
        if not session:
            raise Exception(f"No session matches {session_id}")

        def process(
            header: SMB2Header,
            raw: memoryview,
            message_offset: int,
            state: typing.Dict[str, typing.Any],
        ) -> Event:
            if header.status != 0:
                raise unpack_error_response(header, raw, message_offset)[0]

            message = LogoffResponse.unpack(raw, message_offset, message_offset)[0]
            session = typing.cast(ClientSession, state["session"])
            del session.connection.session_table[session.session_id]

            return MessageReceived(header, message)

        return self.send(
            LogoffRequest(),
            session_id=session_id,
            callback=process,
            callback_state={"session": session},
        )

    def tree_connect(
        self,
        session_id: int,
        path: str,
        contexts: typing.Optional[typing.List[TreeContext]] = None,
    ) -> ClientPendingRequest:
        if not self.connection:
            raise Exception("No connection has been negotiated")

        session = self.connection.session_table.get(session_id, None)
        if not session:
            raise Exception("No authenticated session")

        path_components = [p for p in path.split("\\") if p]
        if len(path_components) != 2:
            raise Exception("Expecting share path in the format \\\\server\\share")

        flags = TreeConnectFlags.NONE
        if contexts:
            flags |= TreeConnectFlags.EXTENSION_PRESENT

        return self.send(
            TreeConnectRequest(flags=flags, path=path, tree_contexts=contexts or []),
            session_id=session.session_id,
            callback=_process_tree_connect_response,
            callback_state={
                "client": self,
                "config": self.config,
                "session": session,
                "share_path": path,
                "share_name": path_components[1],
            },
        )

    def tree_disconnect(
        self,
        session_id: int,
        tree_id: int,
    ) -> ClientPendingRequest:
        if not self.connection:
            raise Exception("No connection has been negotiated")

        session = self.connection.session_table.get(session_id, None)
        if not session:
            raise Exception("Could not find session")

        tree = session.tree_connect_table.get(tree_id, None)
        if not tree:
            raise Exception("Could not find tree")

        def process(
            header: SMB2Header,
            raw: memoryview,
            message_offset: int,
            state: typing.Dict[str, typing.Any],
        ) -> Event:
            if header.status != 0:
                raise unpack_error_response(header, raw, message_offset)[0]

            message = TreeDisconnectResponse.unpack(raw, message_offset, message_offset)[0]
            tree = typing.cast(ClientTreeConnect, state["tree"])
            del tree.session.tree_connect_table[tree.tree_connect_id]

            return MessageReceived(header, message)

        return self.send(
            TreeDisconnectRequest(),
            session_id=tree.session.session_id,
            tree_id=tree.tree_connect_id,
            callback=process,
            callback_state={"tree": tree},
        )

    def open(
        self,
        tree_id: int,
        session_id: int,
        name: str,
        create_disposition: CreateDisposition,
        impersonation_level: ImpersonationLevel = ImpersonationLevel.IMPERSONATION,
        desired_access: int = 0,
        file_attributes: int = 0,
        share_access: ShareAccess = ShareAccess.NONE,
        create_options: CreateOptions = CreateOptions.NONE,
        oplock_level: RequestedOplockLevel = RequestedOplockLevel.NONE,
    ) -> ClientPendingRequest:
        if not self.connection:
            raise Exception("No connection has been negotiated")

        session = self.connection.session_table.get(session_id, None)
        if not session:
            raise Exception("Could not find session")

        tree = session.tree_connect_table.get(tree_id, None)
        if not tree:
            raise Exception("Could not find tree")

        create = CreateRequest(
            requested_oplock_level=oplock_level,
            impersonation_level=impersonation_level,
            desired_access=desired_access,
            file_attributes=file_attributes,
            share_access=share_access,
            create_disposition=create_disposition,
            create_options=create_options,
            name=name,
        )
        return self.send(
            create,
            session_id=session_id,
            tree_id=tree_id,
            callback=_process_create_response,
            callback_state={
                "tree": tree,
                "request": create,
            },
        )

    def close(
        self,
        file_id: bytes,
        session_id: int,
        query_attrib: bool = False,
    ) -> ClientPendingRequest:
        if not self.connection:
            raise Exception("No connection has been negotiated")

        session = self.connection.session_table.get(session_id, None)
        if not session:
            raise Exception("Could not find session")

        open = session.open_table.get(file_id, None)
        if not open:
            raise Exception("Could not find file")

        def process(
            header: SMB2Header,
            raw: memoryview,
            message_offset: int,
            state: typing.Dict[str, typing.Any],
        ) -> Event:
            if header.status != 0:
                raise unpack_error_response(header, raw, message_offset)[0]

            message = CloseResponse.unpack(raw, message_offset, message_offset)[0]
            session = typing.cast(ClientSession, state["session"])
            file_id = typing.cast(bytes, state["file_id"])
            del session.open_table[file_id]

            return MessageReceived(header, message)

        flags = CloseFlags.NONE
        if query_attrib:
            flags |= CloseFlags.POSTQUERY_ATTRIB

        return self.send(
            CloseRequest(flags=flags, file_id=file_id),
            session_id=session.session_id,
            tree_id=open.tree_connect.tree_connect_id,
            callback=process,
            callback_state={"session": session, "file_id": file_id},
        )

    def read(
        self,
        open: ClientApplicationOpenFile,
        offset: int,
        length: int,
        minimum_length: int = 0,
        unbuffered: bool = False,
        compress: bool = False,
    ) -> ClientPendingRequest:
        def process(
            header: SMB2Header,
            raw: memoryview,
            message_offset: int,
            state: typing.Dict[str, typing.Any],
        ) -> Event:
            if header.status != 0:
                error = unpack_error_response(header, raw, message_offset)[0]
                return ErrorReceived(header, error)

            message = ReadResponse.unpack(raw, message_offset, message_offset)[0]
            return MessageReceived(header, message)

        flags = ReadRequestFlags.NONE
        if unbuffered:
            flags |= ReadRequestFlags.READ_UNBUFFERED
        if compress:
            flags |= ReadRequestFlags.REQUEST_COMPRESSED

        return self.send(
            ReadRequest(
                flags=flags,
                length=length,
                offset=offset,
                file_id=open.file_id,
                minimum_count=minimum_length,
                channel=ReadChannel.NONE,
                remaining_bytes=0,
            ),
            callback=process,
            callback_state={},
            session_id=open.session.session_id,
            tree_id=open.tree_connect.tree_connect_id,
        )

    def write(
        self,
        open: ClientApplicationOpenFile,
        offset: int,
        data: typing.Union[bytes, bytearray, memoryview],
        write_through: bool = False,
        unbuffered_write: bool = False,
        compress_write: bool = False,
    ) -> ClientPendingRequest:
        def process(
            header: SMB2Header,
            raw: memoryview,
            message_offset: int,
            state: typing.Dict[str, typing.Any],
        ) -> Event:
            if header.status != 0:
                raise unpack_error_response(header, raw, message_offset)[0]

            message = WriteResponse.unpack(raw, message_offset, message_offset)[0]
            return MessageReceived(header, message)

        flags = WriteFlags.NONE
        if write_through:
            flags |= WriteFlags.WRITE_THROUGH
        if unbuffered_write:
            flags |= WriteFlags.WRITE_UNBUFFERED

        return self.send(
            WriteRequest(
                offset=offset,
                file_id=open.file_id,
                channel=WriteChannel.NONE,
                remaining_bytes=0,
                flags=flags,
                data=data,
            ),
            callback=process,
            callback_state={},
            session_id=open.session.session_id,
            tree_id=open.tree_connect.tree_connect_id,
        )


def _process_negotiate_response(
    header: SMB2Header,
    raw: memoryview,
    message_offset: int,
    state: typing.Dict[str, typing.Any],
) -> Event:
    if header.status != NtStatus.STATUS_SUCCESS:
        raise unpack_error_response(header, raw, message_offset)[0]

    message = NegotiateResponse.unpack(raw, message_offset, message_offset)[0]
    client = typing.cast(SMBClient, state["client"])
    config = typing.cast(ClientConfig, state["config"])
    connection = typing.cast(ClientConnection, state["connection"])
    server_name = typing.cast(str, state["server_name"])
    transport_identifier = typing.cast(TransportIdentifier, state["transport_identifier"])
    requested_dialects = typing.cast(typing.List[Dialect], state["requested_dialects"])
    requested_preauth_algos = typing.cast(
        typing.Dict[int, typing.Type[HashAlgorithmBase]], state["requested_preauth_algos"]
    )
    requested_ciphers = typing.cast(typing.Dict[Cipher, typing.Type[CipherBase]], state["requested_ciphers"])
    requested_compressors = typing.cast(
        typing.Dict[CompressionAlgorithm, typing.Type[CompressionAlgorithmBase]], state["requested_compressors"]
    )
    requested_signers = typing.cast(
        typing.Dict[SigningAlgorithm, typing.Type[SigningAlgorithmBase]], state["requested_signers"]
    )

    if message.max_transact_size < 65536:
        raise Exception("Negotiated max transact size is less than expected minimum")

    if message.max_read_size < 65536:
        raise Exception("Negotiated max read size is less than expected minimum")

    if message.max_write_size < 65536:
        raise Exception("Negotiated max write size is less than expected minimum")

    connection.max_transact_size = message.max_transact_size
    connection.max_read_size = message.max_read_size
    connection.max_write_size = message.max_write_size
    connection.server_guid = message.server_guid
    connection.gss_negotiate_token = message.security_buffer
    connection.require_signing = bool(message.security_mode & SecurityModes.SIGNING_REQUIRED)

    if message.dialect_revision == Dialect.SMB2_WILDCARD:
        # This should only occur if as_smb1=True is set and the server returns the wildcard dialect. The client
        # needs to create a new connection other than NetBIOS over TCP and re-negotiate.
        if transport_identifier == TransportIdentifier.NETBIOS_TCP:
            raise Exception("Connection should be re-negotiated with a transport other than NetBIOS over Tcp")

        raise Exception("FIXME - need to resend negotiate")

    elif message.dialect_revision not in requested_dialects:
        raise Exception("Selected dialect does not meet one offered by the client")

    connection.dialect = message.dialect_revision

    # Overriden if a newer dialect was chosen
    connection.signing_algorithm_id = HMACSHA256SigningAlgorithm()

    if message.dialect_revision >= Dialect.SMB210:
        connection.supports_file_leasing = bool(message.capabilities & Capabilities.LEASING)
        connection.supports_multi_credit = bool(message.capabilities & Capabilities.LARGE_MTU)

    if message.dialect_revision >= Dialect.SMB300:
        connection.supports_directory_leasing = bool(message.capabilities & Capabilities.DIRECTORY_LEASING)
        connection.supports_multi_channel = bool(message.capabilities & Capabilities.MULTI_CHANNEL)
        connection.server_capabilities = message.capabilities
        connection.server_security_mode = message.security_mode

        if message.dialect_revision < Dialect.SMB311:
            connection.supports_encryption = bool(message.capabilities & Capabilities.ENCRYPTION)

        if not connection.server:
            connection.server = config.server_list.setdefault(
                server_name,
                ClientServer(
                    server_guid=message.server_guid,
                    dialect_revision=message.dialect_revision,
                    capabilities=message.capabilities,
                    security_mode=message.security_mode,
                    address_list=[],
                    server_name=server_name,
                ),
            )

        if connection.server.server_guid != message.server_guid:
            raise Exception("Server GUID does not match registered server")

        if connection.server.dialect_revision != message.dialect_revision:
            raise Exception("Server Dialect does not match registered dialect")

        if connection.server.security_mode != message.security_mode:
            raise Exception("Server security mode does not match registered security mode")

        if connection.server.capabilities != message.capabilities:
            raise Exception("Server capabilities does not match registered capabilities")

        # Overriden by the below if another was negotiated
        connection.signing_algorithm_id = AESCMACSigningAlgorithm()
        connection.cipher_id = AES128CCMCipher()

    if message.dialect_revision >= Dialect.SMB311:
        found_contexts: typing.Set[ContextType] = set()
        for context in message.negotiate_contexts:
            if context.context_type in found_contexts:
                raise Exception(f"Found multiple context {context.context_type}")
            found_contexts.add(context.context_type)

            if isinstance(context, PreauthIntegrityCapabilities):
                if len(context.hash_algorithms) != 1:
                    raise Exception(f"Found {len(context.hash_algorithms)} algorithms, expecting 1")

                algorithm_id = context.hash_algorithms[0]
                if algorithm_id not in requested_preauth_algos:
                    raise Exception("Unexpected pre auth hash algorithm selected")

                connection.preauth_integrity_hash_id = requested_preauth_algos[algorithm_id]()

            elif isinstance(context, EncryptionCapabilities):
                if len(context.ciphers) != 1:
                    raise Exception(f"Found {len(context.ciphers)} ciphers, expecting 1")

                if context.ciphers[0] != 0:
                    cipher_id = context.ciphers[0]
                    if cipher_id not in requested_ciphers:
                        raise Exception("Unexpected cipher selected")

                    connection.cipher_id = requested_ciphers[cipher_id]()

            elif isinstance(context, SigningCapabilities):
                if len(context.signing_algorithms) != 1:
                    raise Exception(f"Found {len(context.signing_algorithms)} algorithms, expecting 1")

                sign_algo_id = context.signing_algorithms[0]
                if sign_algo_id not in requested_signers:
                    raise Exception("Unexpected signing algorithm selected")

                connection.signing_algorithm_id = requested_signers[sign_algo_id]()

        if not connection.preauth_integrity_hash_id:
            raise Exception("Was expecting at least 1 preauth int cap")

        # Need to hash both the original request and the response now the algorithm has been negotiated.
        request = connection.outstanding_requests[header.message_id]
        new_hash = connection.preauth_integrity_hash_id.hash((b"\x00" * 64) + request.message)
        connection.preauth_integrity_hash_value = connection.preauth_integrity_hash_id.hash(new_hash + bytes(raw))

    config.connection_table[server_name] = client.connection = connection
    return ProtocolNegotiated(header, message, connection)


def _process_session_setup_response(
    header: SMB2Header,
    raw: memoryview,
    message_offset: int,
    state: typing.Dict[str, typing.Any],
) -> Event:
    session = typing.cast(ClientSession, state["session"])
    connection = session.connection

    if header.status not in [NtStatus.STATUS_SUCCESS, NtStatus.STATUS_MORE_PROCESSING_REQUIRED]:
        raise unpack_error_response(header, raw, message_offset)[0]

    message = SessionSetupResponse.unpack(raw, message_offset, message_offset)[0]
    if header.session_id in connection.session_table:
        raise Exception("FIXME - implement reauthentication/channel session setup")

    session.session_id = header.session_id
    connection.preauth_session_table.setdefault(header.session_id, session)

    if header.status == NtStatus.STATUS_SUCCESS:
        return SessionAuthenticated(header, message, session, bytes(raw))
    else:
        if connection.preauth_integrity_hash_id:
            session.preauth_integrity_hash_value = connection.preauth_integrity_hash_id.hash(
                session.preauth_integrity_hash_value + bytes(raw)
            )

        return SessionProcessingRequired(header, message)


def _process_tree_connect_response(
    header: SMB2Header,
    raw: memoryview,
    message_offset: int,
    state: typing.Dict[str, typing.Any],
) -> Event:
    if header.status != NtStatus.STATUS_SUCCESS:
        raise unpack_error_response(header, raw, message_offset)[0]

    message = TreeConnectResponse.unpack(raw, message_offset, message_offset)[0]
    client = typing.cast(SMBClient, state["client"])
    config = typing.cast(ClientConfig, state["config"])
    session = typing.cast(ClientSession, state["session"])
    share_path = typing.cast(str, state["share_path"])
    share_name = typing.cast(str, state["share_name"])

    encrypt_data = bool(message.share_flags & ShareFlags.ENCRYPT_DATA)

    tree_connect = ClientTreeConnect(
        share_name=share_name,
        tree_connect_id=header.tree_id,
        session=session,
        is_dfs_share=bool(message.share_flags & ShareFlags.DFS),
        is_ca_share=bool(message.capabilities & ShareCapabilities.CONTINUOUS_AVAILABILITY),
        encrypt_data=encrypt_data,
        is_scaleout_share=False,
        compress_data=bool(message.share_flags & ShareFlags.COMPRESS_DATA),
        share_type=message.share_type,
    )
    config.share_list.setdefault(
        share_path,
        ClientShare(
            path_name=share_path,
            encrypt_data=encrypt_data,
            share_type=message.share_type,
        ),
    )

    if (
        session.connection.dialect >= Dialect.SMB300
        and session.connection.dialect < Dialect.SMB311
        and config.require_secure_negotiate
    ):
        validate = ValidateNegotiateInfoRequest(
            capabilities=session.connection.client_capabilities,
            guid=session.connection.client_guid,
            security_mode=session.connection.client_security_mode,
            dialects=session.connection.offered_dialects,
        )
        ioctl = IOCTLRequest(
            ctl_code=validate.ctl_code,
            file_id=validate.file_id,
            flags=validate.flags,
            max_output_response=validate.max_output_response,
            input=bytes(validate.pack()),
        )
        client.send(
            ioctl,
            session_id=session.session_id,
            tree_id=header.tree_id,
            callback=_process_validate_negotiate_info_response,
            callback_state={"session": session, "tree": tree_connect, "header": header, "message": message},
            must_sign=True,
        )

        # Do not send a TreeConnecteed event as the validation needs a response to continue.
        return MessageReceived(header, message, data_available=True)

    else:
        session.tree_connect_table[header.tree_id] = tree_connect
        return TreeConnected(header, message, tree_connect)


def _process_validate_negotiate_info_response(
    header: SMB2Header,
    raw: memoryview,
    message_offset: int,
    state: typing.Dict[str, typing.Any],
) -> Event:
    # FIXME: Ignore FileClosed, InvalidDeviceRequest, NotSupported as long as the header had a signature
    if header.status != NtStatus.STATUS_SUCCESS:
        raise unpack_error_response(header, raw, message_offset)[0]

    message = IOCTLResponse.unpack(raw, message_offset, message_offset)[0]
    session = typing.cast(ClientSession, state["session"])
    tree = typing.cast(ClientTreeConnect, state["tree"])
    tree_header = typing.cast(SMB2Header, state["header"])
    tree_message = typing.cast(TreeConnectResponse, state["message"])

    validate = ValidateNegotiateInfoResponse.unpack(message.output)
    if validate.capabilities != session.connection.server_capabilities:
        raise Exception("Invalid capabilities")

    if validate.guid != session.connection.server_guid:
        raise Exception("Invalid server guid")

    if validate.security_mode != session.connection.server_security_mode:
        raise Exception("Invalid security mode")

    if validate.dialect != session.connection.dialect:
        raise Exception("Invalid dialect")

    # FIXME: Invalid all sessions in connection table if any of the above fail
    session.tree_connect_table[header.tree_id] = tree

    return TreeConnected(tree_header, tree_message, tree)


def _process_create_response(
    header: SMB2Header,
    raw: memoryview,
    message_offset: int,
    state: typing.Dict[str, typing.Any],
) -> Event:
    if header.status != NtStatus.STATUS_SUCCESS:
        raise unpack_error_response(header, raw, message_offset)[0]

    message = CreateResponse.unpack(raw, message_offset, message_offset)[0]
    tree = typing.cast(ClientTreeConnect, state["tree"])
    session = tree.session
    request = typing.cast(CreateRequest, state["request"])

    file_name = request.name if tree.is_dfs_share else f"{session.connection.server_name}\\{request.name}"
    open = ClientApplicationOpenFile(
        file_id=message.file_id,
        tree_connect=tree,
        connection=session.connection,
        session=session,
        oplock_level=message.oplock_level,
        durable=False,
        resiliant_handle=False,
        last_disconnect_time=0,
        desired_access=request.desired_access,
        share_mode=request.share_access,
        create_options=request.create_options,
        file_attributes=request.file_attributes,
        create_disposition=request.create_disposition,
        file_name=file_name,
        # Find out what these default should be
        resilient_timeout=0,
        operation_bucket=[],
        durable_timeout=0,
        outstanding_requests={},
        create_guid=uuid.UUID(int=0),
        is_persistent=False,
    )
    session.open_table[message.file_id] = open

    return FileOpened(header, message, open)
