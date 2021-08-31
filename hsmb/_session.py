# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import hashlib
import hmac
import typing

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import cmac, hashes
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC, CounterLocation, Mode

from hsmb._connection import PendingRequest, SMBClientConnection
from hsmb._crypto import smb3kdf
from hsmb._events import Event, SecurityTokenReceived
from hsmb._headers import HeaderFlags, SMB2Header
from hsmb._messages import (
    MESSAGES,
    Capabilities,
    Dialect,
    LogoffRequest,
    SecurityModes,
    SessionFlags,
    SessionSetupFlags,
    SessionSetupRequest,
    SessionSetupResponse,
)
from hsmb._negotiate_contexts import Cipher


class SMBClientSession:
    def __init__(
        self,
        connection: SMBClientConnection,
    ) -> None:
        self.session_id = 0
        self.tree_connect_table: typing.Dict[int, typing.Any] = {}
        self.session_key: typing.Optional[bytes] = None
        self.signing_required = False
        self.connection = connection
        self.open_table: typing.Dict[int, typing.Any] = {}
        self.is_anonymous = False
        self.is_guest = False
        self.channel_list: typing.List = []
        self.encrypt_data = False
        self.encryption_key: typing.Optional[bytes] = None
        self.decryption_key: typing.Optional[bytes] = None
        self.signing_key: typing.Optional[bytes] = None
        self.application_key: typing.Optional[bytes] = None
        self.preauth_integrity_hash_value = connection.preauth_integrity_hash_value
        self.full_session_key: typing.Optional[bytes] = None

        self._validation_info: typing.Optional[typing.Tuple[SMB2Header, SessionSetupResponse, bytearray]] = None

    def __enter__(self) -> "SMBClientSession":
        return self

    def __exit__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        self.close()

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

        send_view = self.connection.send(req, session_id=self.session_id, callback=self._process_session_setup)

        if self.connection.preauth_integrity_hash_id:
            self.preauth_integrity_hash_value = self.connection.preauth_integrity_hash_id.hash(
                self.preauth_integrity_hash_value + bytes(send_view)
            )

    def set_session_key(
        self,
        key: bytes,
    ) -> None:
        if self.full_session_key:
            raise Exception("Session key has already been set")
        elif not self._validation_info:
            raise Exception("Cannot set session key until last session setup request was received")

        header, message, raw_header = self._validation_info
        if self.connection.dialect >= Dialect.SMB311 and not header.flags & HeaderFlags.SIGNED:
            raise Exception("Header was not signed")

        self.connection.session_table[self.session_id] = self.connection.preauth_session_table.pop(self.session_id)

        self.full_session_key = key
        self.session_key = key[:16].ljust(16, b"\x00")

        if self.connection.dialect >= Dialect.SMB311:
            self.signing_key = smb3kdf(self.session_key, b"SMBSigningKey\x00", self.preauth_integrity_hash_value)
            self.application_key = smb3kdf(self.session_key, b"SMBAppKey\x00", self.preauth_integrity_hash_value)

            key = self.session_key
            length = 16

            if self.connection.cipher_id and self.connection.cipher_id.cipher_id() in [
                Cipher.AES256_CCM,
                Cipher.AES256_GCM,
            ]:
                key = self.full_session_key
                length = 32

            self.encryption_key = smb3kdf(key, b"SMBC2SCipherKey\x00", self.preauth_integrity_hash_value, length=length)
            self.decryption_key = smb3kdf(key, b"SMBS2CCipherKey\x00", self.preauth_integrity_hash_value, length=length)

        elif self.connection.dialect >= Dialect.SMB300:
            self.signing_key = smb3kdf(self.session_key, b"SMB2AESCMAC\x00", b"SmbSign\x00")
            self.application_key = smb3kdf(self.session_key, b"SMB2APP\x00", b"SmbRpc\x00")
            self.encryption_key = smb3kdf(self.session_key, b"SMB2AESCCM\x00", b"ServerIn \x00")
            self.decryption_key = smb3kdf(self.session_key, b"SMB2AESCCM\x00", b"ServerOut\x00")

        else:
            self.signing_key = self.session_key
            self.application_key = self.session_key

        self.signing_required = self.connection.config.require_message_signing or self.connection.require_signing
        if message.session_flags & SessionFlags.ENCRYPT_DATA:
            self.signing_required = False
            self.encrypt_data = True

        if self.signing_required:
            if message.session_flags & SessionFlags.IS_GUEST:
                raise Exception("Cannot sign as a guest account")

            expected_signature = header.signature
            memoryview(raw_header)[48:64] = b"\x00" * 16

            actual_signature = self.connection.signing_algorithm_id.sign(self.signing_key, header, bytes(raw_header))

            if actual_signature != expected_signature:
                raise Exception("Signature mismatch")

    def _process_session_setup(
        self,
        header: SMB2Header,
        message: SessionSetupResponse,
        raw: memoryview,
    ) -> typing.Optional[SecurityTokenReceived]:
        self.session_id = header.session_id
        self.connection.preauth_session_table.setdefault(self.session_id, self)

        require_session_key = False
        if header.status == 0:
            require_session_key = True
            self._validation_info = (header, message, bytearray(raw))

        elif self.connection.preauth_integrity_hash_id:
            self.preauth_integrity_hash_value = self.connection.preauth_integrity_hash_id.hash(
                self.preauth_integrity_hash_value + bytes(raw)
            )

        if message.security_buffer or require_session_key:
            return SecurityTokenReceived(
                session_id=self.session_id,
                token=message.security_buffer,
                require_session_key=require_session_key,
            )

        return None

    def close(self) -> None:
        self.connection.send(LogoffRequest(), session_id=self.session_id)
