# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing
import uuid

from hsmb._headers import HeaderFlags, PacketHeaderSync
from hsmb._messages import (
    Capabilities,
    Dialect,
    NegotiateRequest,
    SecurityModes,
    SMBMessage,
)


class SMBConnection:
    def __init__(
        self,
    ) -> None:
        self.require_message_signing = True
        self.is_encryption_supported = True
        self.is_compression_supported = False
        self.is_changed_compression_supported = False
        self.is_rdma_transform_supported = False
        self.disable_encryption_over_secure_transport = False

        self._data_to_send = bytearray()

    def send(
        self,
        message: SMBMessage,
    ) -> None:
        header = PacketHeaderSync(
            credit_charge=0,
            channel_sequence=0,
            status=0,
            command=message.command,
            credits=0,
            flags=HeaderFlags.none,
            next_command=0,
            message_id=0,
            tree_id=0,
            session_id=0,
            signature=b"",
        )

        a = ""

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


class SMBClient(SMBConnection):
    def __init__(
        self,
    ) -> None:
        self.global_file_table: typing.Dict[str, typing.Any] = {}
        self.client_guid = uuid.uuid4()
        self.max_dialect = Dialect.smb311
        self.require_secure_negotiate = True
        self.server_list: typing.Dict[str, typing.Any] = {}
        self.share_list: typing.Dict[str, typing.Any] = {}
        self.compress_all_requests = False

    def negotiate(
        self,
        dialects: typing.Optional[typing.List[Dialect]] = None,
    ) -> None:
        if dialects is not None:
            nego_dialects = dialects
        else:
            nego_dialects = [
                Dialect.smb202,
                Dialect.smb210,
                Dialect.smb300,
                Dialect.smb302,
                Dialect.smb311,
            ]

        security_mode = SecurityModes.signing_enabled
        if self.require_message_signing:
            security_mode |= SecurityModes.signing_required

        capabilities = Capabilities.none

        self.send(
            NegotiateRequest(
                dialects=nego_dialects,
                security_mode=security_mode,
                capabilities=capabilities,
                client_guid=self.client_guid,
                negotiate_contexts=[],
            )
        )

    def session_setup(self) -> None:
        pass

    def logoff(self) -> None:
        pass

    def tree_connect(self) -> None:
        pass

    def create(self) -> None:
        pass

    def close(self) -> None:
        pass

    def flush(self) -> None:
        pass

    def read(self) -> None:
        pass

    def write(self) -> None:
        pass

    def oplock_break(self) -> None:
        pass

    def lock(self) -> None:
        pass

    def echo(self) -> None:
        pass

    def cancel(self) -> None:
        pass

    def ioctl(self) -> None:
        pass

    def query_directory(self) -> None:
        pass

    def change_notify(self) -> None:
        pass

    def set_info(self) -> None:
        pass
