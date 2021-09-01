# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import enum
import os
import typing
import uuid

from hsmb._client import (
    ClientConfig,
    ClientConnection,
    ClientPendingRequest,
    ClientServer,
    ClientSession,
    ClientTreeConnect,
    ResponseCallback,
)
from hsmb._crypto import (
    AES128CCMCipher,
    AESCMACSigningAlgorithm,
    HMACSHA256SigningAlgorithm,
    smb3kdf,
)
from hsmb._events import (
    Event,
    MessageReceived,
    ProtocolNegotiated,
    SessionAuthenticated,
    SessionProcessingRequired,
    TreeConnected,
)
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
    LogoffRequest,
    LogoffResponse,
    NegotiateRequest,
    NegotiateResponse,
    SecurityModes,
    SessionFlags,
    SessionSetupFlags,
    SessionSetupRequest,
    SessionSetupResponse,
    ShareCapabilities,
    ShareFlags,
    ShareType,
    SMB1NegotiateRequest,
    SMB1NegotiateResponse,
    SMBMessage,
    TreeConnectFlags,
    TreeConnectRequest,
    TreeConnectResponse,
    TreeDisconnectRequest,
    TreeDisconnectResponse,
)
from hsmb._negotiate_contexts import (
    Cipher,
    CipherBase,
    CompressionAlgorithm,
    CompressionAlgorithmBase,
    CompressionCapabilities,
    CompressionCapabilityFlags,
    ContextType,
    EncryptionCapabilities,
    HashAlgorithm,
    HashAlgorithmBase,
    NegotiateContext,
    NetnameNegotiate,
    PreauthIntegrityCapabilities,
    RdmaTransformCapabilities,
    RdmaTransformId,
    SigningAlgorithm,
    SigningAlgorithmBase,
    SigningCapabilities,
    TransportCapabilities,
    TransportCapabilityFlags,
)
from hsmb._tree_contexts import TreeContext


class TransportIdentifier(enum.Enum):
    UNKNOWN = enum.auto()
    DIRECT_TCP = enum.auto()
    NETBIOS_TCP = enum.auto()
    QUIC = enum.auto()


class SMBClient:
    def __init__(
        self,
        config: ClientConfig,
    ) -> None:
        self.config = config
        self.connection: typing.Optional[ClientConnection] = None
        self._data_to_send = bytearray()
        self._receive_buffer = bytearray()

    def send(
        self,
        message: SMBMessage,
        channel_sequence: int = 0,
        credits: int = 0,
        related: bool = False,
        priority: typing.Optional[int] = None,
        session_id: int = 0,
        tree_id: int = 0,
        final: bool = True,
        callback: typing.Optional[ResponseCallback] = None,
        callback_state: typing.Optional[typing.Dict[str, typing.Any]] = None,
    ) -> memoryview:
        if not self.connection:
            raise Exception("Cannot send any message without a negotiated connection")

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
            if self.connection.supports_multi_credit:
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
        self.connection.outstanding_requests[message_id] = ClientPendingRequest(
            message=message,
            receive_callback=callback,
            receive_callback_state=callback_state,
        )

        raw_data = header.pack()
        raw_data += message.pack(len(raw_data))

        if flags & HeaderFlags.SIGNED:
            signature = self.connection.signing_algorithm_id.sign(session.signing_key, header, bytes(raw_data))
            memoryview(raw_data)[48:64] = signature

        if session and session.encrypt_data:
            raw_data = self.connection.cipher_id.encrypt(session.encryption_key, header, bytes(raw_data))

        offset = len(self._data_to_send)
        self._data_to_send += raw_data

        return memoryview(self._data_to_send)[offset : len(raw_data)]

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
        if not self.connection:
            raise Exception("Cannot process any events until a connection is created")

        raw = memoryview(self._receive_buffer)
        if not raw:
            return None

        header, offset = unpack_header(raw)

        if isinstance(header, TransformHeader):
            if not self.connection.cipher_id:
                raise Exception("Received encrypted message but no cipher was available for decryption")

            session = self.connection.session_table[header.session_id]
            decrypted_data = self.connection.cipher_id.decrypt(
                session.decryption_key, header, bytes(self._receive_buffer)
            )
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

        command = header.command
        next_command = header.next_command
        message_id = header.message_id
        granted_credits = header.credits
        self.connection.sequence_window[-1] = (
            self.connection.sequence_window[-1][0],
            self.connection.sequence_window[-1][1] + granted_credits,
        )

        message_cls = MESSAGES[command][1]
        message, message_offset = message_cls.unpack(self._receive_buffer, offset, offset)
        raw = raw[: offset + message_offset]

        if next_command:
            self._receive_buffer = self._receive_buffer[next_command:]
        else:
            # In case the message still contained padded bytes strip off the remaining NULL bytes.
            self._receive_buffer = self._receive_buffer[offset + message_offset :].lstrip(b"\x00")

        request = self.connection.outstanding_requests[message_id]
        if request.receive_callback:
            new_event = request.receive_callback(header, message, raw, request.receive_callback_state or {})
            if new_event:
                return new_event

        return MessageReceived(header, message)

    def negotiate(
        self,
        server_name: str,
        offered_dialects: typing.Optional[typing.List[Dialect]] = None,
        transport_identifier: TransportIdentifier = TransportIdentifier.UNKNOWN,
    ) -> None:
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
        send_view = self.send(msg, callback=_process_negotiate_response, callback_state=callback_state)
        connection.preauth_integrity_hash_value = bytes(send_view)

    def session_setup(
        self,
        security_buffer: bytes,
        session_id: int = 0,
        previous_session_id: int = 0,
    ) -> None:
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
        req = SessionSetupRequest(
            flags=SessionSetupFlags.NONE,
            security_mode=security_mode,
            capabilities=Capabilities.DFS,
            channel=0,
            previous_session_id=previous_session_id,
            security_buffer=security_buffer,
        )

        callback_state = {
            "session": session,
        }
        send_view = self.send(
            req,
            session_id=session.session_id,
            callback=_process_session_setup_response,
            callback_state=callback_state,
        )

        if self.connection.preauth_integrity_hash_id:
            pre_hash = session.preauth_integrity_hash_value or self.connection.preauth_integrity_hash_value
            session.preauth_integrity_hash_value = self.connection.preauth_integrity_hash_id.hash(
                pre_hash + bytes(send_view)
            )

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
    ) -> None:
        if not self.connection:
            raise Exception("No connection has been negotiated")

        session = self.connection.session_table.get(session_id, None)
        if not session:
            raise Exception(f"No session matches {session_id}")

        def process(
            header: SMB2Header,
            message: SMBMessage,
            raw: memoryview,
            state: typing.Dict[str, typing.Any],
        ) -> typing.Optional[Event]:
            if header.status != 0:
                raise Exception(f"Received error status {header.status:8X}")

            session = typing.cast(ClientSession, state["session"])
            del session.connection.session_table[session.session_id]
            return None

        self.send(
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
    ) -> None:
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

        self.send(
            TreeConnectRequest(flags=flags, path=path, tree_contexts=contexts or []),
            session_id=session.session_id,
            callback=_process_tree_connect_response,
            callback_state={"session": session, "share_name": path_components[1]},
        )

    def tree_disconnect(
        self,
        session_id: int,
        tree_id: int,
    ) -> None:
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
            message: SMBMessage,
            raw: memoryview,
            state: typing.Dict[str, typing.Any],
        ) -> typing.Optional[Event]:
            if header.status != 0:
                raise Exception("Invalid status")

            tree = typing.cast(ClientTreeConnect, state["tree"])
            del tree.session.tree_connect_table[tree.tree_connect_id]

            return None

        self.send(
            TreeDisconnectRequest(),
            session_id=tree.session.session_id,
            tree_id=tree.tree_connect_id,
            callback=process,
            callback_state={"tree": tree},
        )


def _process_negotiate_response(
    header: SMB2Header,
    message: SMBMessage,
    raw: memoryview,
    state: typing.Dict[str, typing.Any],
) -> typing.Optional[Event]:
    message = typing.cast(NegotiateResponse, message)
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

    if header.status != 0:
        raise Exception(f"Invalid status {header.status}")

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

        # The current value contains the full request - replace this with the hash value now the hash algorithm
        # has been negotiated.
        new_hash = connection.preauth_integrity_hash_id.hash((b"\x00" * 64) + connection.preauth_integrity_hash_value)
        connection.preauth_integrity_hash_value = connection.preauth_integrity_hash_id.hash(new_hash + bytes(raw))

    config.connection_table[server_name] = client.connection = connection
    return ProtocolNegotiated(header, message, connection)


def _process_session_setup_response(
    header: SMB2Header,
    message: SMBMessage,
    raw: memoryview,
    state: typing.Dict[str, typing.Any],
) -> typing.Optional[Event]:
    message = typing.cast(SessionSetupResponse, message)
    session = typing.cast(ClientSession, state["session"])
    connection = session.connection

    if header.session_id in connection.session_table:
        raise Exception("FIXME - implement reauthentication/channel session setup")

    session.session_id = header.session_id
    if header.status == 0:
        return SessionAuthenticated(header, message, session, bytes(raw))

    elif header.status == 0xC0000016:  # STATUS_MORE_PROCESSING_REQUIRED
        connection.preauth_session_table.setdefault(header.session_id, session)

        if connection.preauth_integrity_hash_id:
            session.preauth_integrity_hash_value = connection.preauth_integrity_hash_id.hash(
                session.preauth_integrity_hash_value + bytes(raw)
            )

        return SessionProcessingRequired(header, message)

    else:
        raise Exception(f"Received error during sessions setup 0x{header.status:8X}")


def _process_tree_connect_response(
    header: SMB2Header,
    message: SMBMessage,
    raw: memoryview,
    state: typing.Dict[str, typing.Any],
) -> typing.Optional[Event]:
    message = typing.cast(TreeConnectResponse, message)

    session = typing.cast(ClientSession, state["session"])
    share_name = typing.cast(str, state["share_name"])

    if header.status == 0xC05D0001:
        raise Exception("STATUS_SMB_BAD_CLUSTER_DIALECT")

    if header.status == 0:
        tree_connect = ClientTreeConnect(
            share_name=share_name,
            tree_connect_id=header.tree_id,
            session=session,
            is_dfs_share=bool(message.share_flags & ShareFlags.DFS),
            is_ca_share=bool(message.capabilities & ShareCapabilities.CONTINUOUS_AVAILABILITY),
            encrypt_data=bool(message.share_flags & ShareFlags.ENCRYPT_DATA),
            is_scaleout_share=False,
            compress_data=bool(message.share_flags & ShareFlags.COMPRESS_DATA),
        )
        session.tree_connect_table[header.tree_id] = tree_connect

        return TreeConnected(header, message, tree_connect)

    else:
        raise Exception(f"Error status {header.status:8X}")


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
