# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""The crypto/compression provider interfaces.

Defines the crypto/compression provider interfaces that is used during a SMB
connection.
"""

import abc
import typing

from hsmb.messages import (
    Cipher,
    CompressionAlgorithm,
    CompressionTransform,
    HashAlgorithm,
    SigningAlgorithm,
    SMB2Header,
    TransformHeader,
)


class HashingProvider(metaclass=abc.ABCMeta):
    """Hashing provider.

    The base class used to implement a provider for hashing SMB data. The
    hashing provider is used to generate the pre authentication integrity
    values during the negotiation and session setup stage. The currently
    known algorithms are defined at :class:`HashAlgorithm` which is based
    on `MS-SMB2 2.2.3.1.1 SMB2_PREAUTH_INTEGRITY_CAPABILITIES`_.

    .. _MS-SMB2 2.2.3.1.1 SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a07bd66-4734-4af8-abcf-5a44ff7ee0e5
    """

    @property
    @abc.abstractmethod
    def algorithm_id(self) -> HashAlgorithm:
        """The hash algorithm the provider implements."""

    @abc.abstractmethod
    def hash(
        self,
        data: bytes,
    ) -> bytes:
        """Hash the data.

        Returns a hash of the data specified based on the algorithm the
        provider implements.

        Args:
            data: A view of the data to hash.

        Returns:
            bytes: The hash of the data.
        """


class EncryptionProvider(metaclass=abc.ABCMeta):
    """Encryption provider.

    The base class used to implement a provider for encrypting and decrypting
    SMB data. The currently known algorithms are defined at :class:`Cipher`
    which is based on `MS-SMB2 2.2.3.1.2 SMB2_ENCRYPTION_CAPABILITIES`_.

    .. _MS-SMB2 2.2.3.1.2 SMB2_ENCRYPTION_CAPABILITIES:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/16693be7-2b27-4d3b-804b-f605bde5bcdd
    """

    @property
    @abc.abstractmethod
    def cipher_id(self) -> Cipher:
        """The cipher identifier the provider implements."""

    @abc.abstractmethod
    def encrypt(
        self,
        header: SMB2Header,
        data: bytearray,
        key: bytes,
    ) -> bytearray:
        """Encrypt the data.

        Encrypts the SMB data based on the algorithm the provider implements.

        Args:
            header: The header of the first message in the data provided.
            data: The data to encrypt including the packed header specified.
            key: The key to use for encryption.

        Returns:
            bytearray: The packed :class:`TransformHeader` of the encrypted
            SMB payload that was passed in.
        """

    @abc.abstractmethod
    def decrypt(
        self,
        header: TransformHeader,
        data: bytearray,
        key: bytes,
    ) -> bytearray:
        """Decrypt the data.

        Decrypts the SMB data based on the algorithm the provider implements.

        Args:
            header: The :class:`TransformHeader` containing the transform
                information to decrypt.
            data: The full transform data, including the header, to decrypt.
            key: The key to use for decryption.

        Returns:
            bytearray: The raw decrypted data.
        """


class CompressionProvider(metaclass=abc.ABCMeta):
    """Compression provider.

    The base class used to implement a provider for compressing and
    decompressing SMB data. The currently known compression algorithms are
    defined at :class:`CompressionAlgorithm` which is based on
    `MS-SMB2 2.2.3.1.3 SMB2_COMPRESSION_CAPABILITIES`_.

    A compression provider can implement multiple compression algorithms and it
    is up to the provider to decide which one(s) to use during compression. A
    provider may opt to not compress data at all if it determines compression
    is not useful or possible based on the input data.

    .. _MS-SMB2 2.2.3.1.3 SMB2_COMPRESSION_CAPABILITIES:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/78e0c942-ab41-472b-b117-4a95ebe88271
    """

    @property
    @abc.abstractmethod
    def compression_ids(self) -> typing.List[CompressionAlgorithm]:
        """A list of compression algorithms the provider implements."""

    @property
    @abc.abstractmethod
    def can_chain(self) -> bool:
        """Whether the provider can create a chained compression buffer."""

    @abc.abstractmethod
    def compress(
        self,
        algorithms: typing.List[CompressionAlgorithm],
        data: bytearray,
        hints: typing.List[slice],
        supports_chaining: bool,
    ) -> bytearray:
        """Compresses the data.

        Compresses the SMB data with the algorithms available. Compression is
        entirely optional and the provider can return the passed in data if
        compression is unavailable or not possible based on the input data. A
        provider SHOULD ensure that the compressed payload is at least smaller
        than the data passed in. If it is larger than the provider SHOULD just
        return the data as it was.

        Args:
            algorithms: A list of algorithms that the peer understands and can
                be used for compression.
            data: The data to compress.
            hints: Optional hints which indicate slices in data which should be
                compressed.
            supports_chaining: Whether the peer supports chained compression
                payloads.

        Returns:
            bytearray: The packed :class:`CompressionTransform` of the
            compressed SMB payload that was passed in.
        """

    @abc.abstractmethod
    def decompress(
        self,
        header: CompressionTransform,
    ) -> bytearray:
        """Decompresses the data.

        Decompresses the SMB data based on the passed in transformation
        payload.

        Args:
            header: The compression payload which contains the compressed data
                which needs to be decompressed.

        Returns:
            bytearray: The decompressed data.
        """


class SigningProvider(metaclass=abc.ABCMeta):
    """Signing provider.

    The base class used to implement a provider for signing SMB data. The
    signing algorithm is fixed for older SMB dialects but is now negotiable
    since SMB 3.x and WIndows 10 v20H2. The currently known algorithms are
    defined at :class:`SigningAlgorithm` which is based on
    `MS-SMB2 2.2.3.1.7 SMB2_SIGNING_CAPABILITIES`_.

    .. _MS-SMB2 2.2.3.1.7 SMB2_SIGNING_CAPABILITIES:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/cb9b5d66-b6be-4d18-aa66-8784a871cc10
    """

    @property
    @abc.abstractmethod
    def signing_id(self) -> SigningAlgorithm:
        """The signing algorithm the provider implements."""

    @abc.abstractmethod
    def sign(
        self,
        header: SMB2Header,
        data: bytearray,
        key: bytes,
    ) -> bytes:
        """Signs the data.

        Signs the data provided using the algorithm the provider implements.

        Args:
            header: The structure header portion of the data provided.
            data: The full SMB message to sign.
            key: The key used to sign the data.

        Returns:
            bytearray: The signature generated for the input data.
        """
