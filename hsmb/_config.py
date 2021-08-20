# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import datetime
import enum
import typing
import uuid


class SMBRole(enum.Enum):
    CLIENT = enum.auto()
    SERVER = enum.auto()


@dataclasses.dataclass
class ServerShare:
    name: str
    encrypt_data: bool = False
    compress_data: bool = False


@dataclasses.dataclass
class SMBConfig:
    role: SMBRole = dataclasses.field(init=False)

    identifier: uuid.UUID = dataclasses.field(default_factory=uuid.uuid4)
    require_message_signing: bool = True
    encryption: bool = True
    compression: bool = True
    chained_compression: bool = True
    rdma_transform: bool = True
    encrypt_with_secure_transport: bool = True

    def register_cipher(self) -> None:
        a = ""

    def register_compressor(self) -> None:
        a = ""

    def register_hasher(self) -> None:
        a = ""


@dataclasses.dataclass
class SMBClientConfig(SMBConfig):
    role = SMBRole.CLIENT

    require_secure_negotiate: bool = True
    compress_all_requests: bool = False


@dataclasses.dataclass
class SMBServerConfig(SMBConfig):
    role = SMBRole.SERVER

    share_list: typing.List[ServerShare] = dataclasses.field(default_factory=list)
    start_time: datetime.datetime = dataclasses.field(default_factory=datetime.datetime.now)
    dfs_capable: bool = False
    encrypt_data: bool = False
    reject_unencrypted_access: bool = False
    is_multi_channel_capable: bool = False
    allow_anonymous_access: bool = False
    allow_named_pipe_over_quic: bool = False
