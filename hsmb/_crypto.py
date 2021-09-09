# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import hashlib
import hmac
import os
import typing

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import cmac, hashes
from cryptography.hazmat.primitives.ciphers import aead, algorithms
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC, CounterLocation, Mode

from hsmb._provider import EncryptionProvider, HashingProvider, SigningProvider
from hsmb.messages import (
    Cipher,
    Command,
    HashAlgorithm,
    HeaderFlags,
    SigningAlgorithm,
    SMB2Header,
    TransformFlags,
    TransformHeader,
)


def _encrypt_aes(
    algorithm: typing.Union[typing.Type[aead.AESCCM], typing.Type[aead.AESGCM]],
    header: SMB2Header,
    message: bytearray,
    key: bytes,
) -> bytearray:
    if algorithm == aead.AESCCM:
        nonce = os.urandom(11)
    else:
        nonce = os.urandom(12)

    transform = bytearray(
        TransformHeader(
            signature=b"\x00" * 16,
            nonce=nonce + (b"\x00" * (16 - len(nonce))),
            original_message_size=len(message),
            flags=TransformFlags.ENCRYPTED,
            session_id=header.session_id,
        ).pack()
    )

    cipher = algorithm(key)
    enc_data = cipher.encrypt(nonce, bytes(message), bytes(transform[20:]))
    enc_message, signature = enc_data[:-16], enc_data[-16:]

    memoryview(transform)[4:20] = signature
    return transform + enc_message


def _decrypt_aes(
    algorithm: typing.Union[typing.Type[aead.AESCCM], typing.Type[aead.AESGCM]],
    header: TransformHeader,
    message: bytearray,
    key: bytes,
) -> bytearray:
    if algorithm == aead.AESCCM:
        nonce = header.nonce[:11]
    else:
        nonce = header.nonce[:12]

    aad = bytes(message[20:52])
    enc_data = bytes(message[52:]) + header.signature

    cipher = algorithm(key)
    return bytearray(cipher.decrypt(nonce, enc_data, aad))


class SHA512HashAlgorithm(HashingProvider):
    @property
    def algorithm_id(self) -> HashAlgorithm:
        return HashAlgorithm.SHA512

    def hash(
        self,
        data: bytes,
    ) -> bytes:
        return hashlib.sha512(data).digest()


class AES128CCMCipher(EncryptionProvider):
    @property
    def cipher_id(self) -> Cipher:
        return Cipher.AES128_CCM

    def encrypt(
        self,
        header: SMB2Header,
        data: bytearray,
        key: bytes,
    ) -> bytearray:
        return _encrypt_aes(aead.AESCCM, header, data, key)

    def decrypt(
        self,
        header: TransformHeader,
        data: bytearray,
        key: bytes,
    ) -> bytearray:
        return _decrypt_aes(aead.AESCCM, header, data, key)


class AES128GCMCipher(EncryptionProvider):
    @property
    def cipher_id(self) -> Cipher:
        return Cipher.AES128_GCM

    def encrypt(
        self,
        header: SMB2Header,
        data: bytearray,
        key: bytes,
    ) -> bytearray:
        return _encrypt_aes(aead.AESGCM, header, data, key)

    def decrypt(
        self,
        header: TransformHeader,
        data: bytearray,
        key: bytes,
    ) -> bytearray:
        return _decrypt_aes(aead.AESGCM, header, data, key)


class AES256CCMCipher(EncryptionProvider):
    @property
    def cipher_id(self) -> Cipher:
        return Cipher.AES256_CCM

    def encrypt(
        self,
        header: SMB2Header,
        data: bytearray,
        key: bytes,
    ) -> bytearray:
        return _encrypt_aes(aead.AESCCM, header, data, key)

    def decrypt(
        self,
        header: TransformHeader,
        data: bytearray,
        key: bytes,
    ) -> bytearray:
        return _decrypt_aes(aead.AESCCM, header, data, key)


class AES256GCMCipher(EncryptionProvider):
    @property
    def cipher_id(self) -> Cipher:
        return Cipher.AES256_GCM

    def encrypt(
        self,
        header: SMB2Header,
        data: bytearray,
        key: bytes,
    ) -> bytearray:
        return _encrypt_aes(aead.AESGCM, header, data, key)

    def decrypt(
        self,
        header: TransformHeader,
        data: bytearray,
        key: bytes,
    ) -> bytearray:
        return _decrypt_aes(aead.AESGCM, header, data, key)


class HMACSHA256SigningAlgorithm(SigningProvider):
    @property
    def signing_id(self) -> SigningAlgorithm:
        return SigningAlgorithm.HMAC_SHA256

    def sign(
        self,
        header: SMB2Header,
        data: bytearray,
        key: bytes,
    ) -> bytes:
        hmac_algo = hmac.new(key, data, digestmod=hashlib.sha256)
        return hmac_algo.digest()[:16]


class AESCMACSigningAlgorithm(SigningProvider):
    @property
    def signing_id(self) -> SigningAlgorithm:
        return SigningAlgorithm.AES_CMAC

    def sign(
        self,
        header: SMB2Header,
        data: bytearray,
        key: bytes,
    ) -> bytes:
        c = cmac.CMAC(
            algorithms.AES(key),
            backend=default_backend(),  # type: ignore[no-untyped-call]
        )
        c.update(bytes(data))
        return c.finalize()


class AESGMACSigningAlgorithm(SigningProvider):
    @property
    def signing_id(self) -> SigningAlgorithm:
        return SigningAlgorithm.AES_GMAC

    def sign(
        self,
        header: SMB2Header,
        data: bytearray,
        key: bytes,
    ) -> bytes:
        message_info = 0
        if header.flags & HeaderFlags.SERVER_TO_REDIR:
            message_info |= 1

        if header.command == Command.CANCEL:
            message_info |= 2

        nonce = b"".join(
            [
                header.message_id.to_bytes(8, byteorder="little"),
                message_info.to_bytes(4, byteorder="little"),
            ]
        )
        # Unlike AES CMAC there is no GMAC equivalent class in Cryptography. To achieve the same thing encrypt a blank
        # set of data and include the message as additional authenticated data. The return value contains the tag which
        # is the signature. https://stackoverflow.com/questions/26003702/does-openssl-have-gmac-api-and-examples
        signature = aead.AESGCM(key).encrypt(nonce, b"", data)

        return signature


def smb3kdf(
    ki: bytes,
    label: bytes,
    context: bytes,
    length: int = 16,
) -> bytes:
    """SMB 3.x key derivation function.

    See `SMB 3.x key derivation function`_

    Args:
        ki: The session key negotiated between the client and server.
        label: The label/purpose of the key.
        context: Context information for the SMB connection.
        length: The length of the key to generate.

    Returns:
        bytes: The key derived by the KDF as specified by [SP800-108] 5.1.

    .. SMB 3.x key derivation function:
        https://blogs.msdn.microsoft.com/openspecification/2017/05/26/smb-2-and-smb-3-security-in-windows-10-the-anatomy-of-signing-and-cryptographic-keys/
    """
    kdf = KBKDFHMAC(
        algorithm=hashes.SHA256(),
        mode=Mode.CounterMode,
        length=length,
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        label=label,
        context=context,
        fixed=None,
        backend=default_backend(),  # type: ignore[no-untyped-call]
    )
    return kdf.derive(ki)
