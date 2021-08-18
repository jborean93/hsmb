# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import enum


class SMBRole(enum.Enum):
    CLIENT = enum.auto()
    SERVER = enum.auto()


@dataclasses.dataclass(frozen=True)
class SMBConfiguration:
    role: SMBRole
    require_message_signing: bool = True
    encryption: bool = True
    compression: bool = False
    chained_compression: bool = False
    rdma_transform: bool = False
    encryption_with_secure_transport: bool = True
