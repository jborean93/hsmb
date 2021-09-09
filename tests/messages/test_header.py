# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import pytest

from hsmb import MalformedPacket
from hsmb.messages import Command, HeaderFlags, SMB2Header, SMBHeader


def test_unpack_header_too_small() -> None:
    with pytest.raises(MalformedPacket, match="Not enough data to unpack SMB header payload"):
        SMBHeader.unpack(b"123")


def test_unpack_header_invalid_protocol() -> None:
    with pytest.raises(MalformedPacket, match="Unknown SMB Header protocol id 11223344"):
        SMBHeader.unpack(b"\x11\x22\x33\x44")


def test_smb2_header_pack() -> None:
    smb2_header = SMB2Header(
        credit_charge=1,
        channel_sequence=2,  # Channel sequence takes priority over status
        status=3,
        command=Command.NEGOTIATE,
        credits=4,
        flags=HeaderFlags.SIGNED,
        next_command=5,
        message_id=6,
        async_id=0x1122334455667788,  # Will be omitted with no ASYNC flag
        tree_id=0x11223344,
        session_id=9,
        signature=b"\x11" * 16,
    )

    actual = smb2_header.pack()
    assert isinstance(actual, bytearray)
    assert actual == (
        b"\xFE\x53\x4D\x42"
        b"\x40\x00"
        b"\x01\x00"
        b"\x02\x00\x00\x00"
        b"\x00\x00"
        b"\x04\x00"
        b"\x08\x00\x00\x00"
        b"\x05\x00\x00\x00"
        b"\x06\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x44\x33\x22\x11"
        b"\x09\x00\x00\x00\x00\x00\x00\x00"
        b"\x11\x11\x11\x11\x11\x11\x11\x11"
        b"\x11\x11\x11\x11\x11\x11\x11\x11"
    )

    unpacked_header = SMBHeader.unpack(actual)[0]
    assert isinstance(unpacked_header, SMB2Header)
    assert unpacked_header.async_id == 0
    assert unpacked_header.tree_id == 0x11223344


def test_smb2_header_async_status_pack() -> None:
    smb2_header = SMB2Header(
        credit_charge=1,
        channel_sequence=0,
        status=3,
        command=Command.NEGOTIATE,
        credits=4,
        flags=HeaderFlags.ASYNC_COMMAND,
        next_command=5,
        message_id=6,
        async_id=0x1122334455667788,
        tree_id=0x11223344,  # async_id is used when ASYNC_COMMAND is set
        session_id=9,
        signature=b"\x11" * 16,
    )

    actual = smb2_header.pack()
    assert isinstance(actual, bytearray)
    assert actual == (
        b"\xFE\x53\x4D\x42"
        b"\x40\x00"
        b"\x01\x00"
        b"\x03\x00\x00\x00"
        b"\x00\x00"
        b"\x04\x00"
        b"\x02\x00\x00\x00"
        b"\x05\x00\x00\x00"
        b"\x06\x00\x00\x00\x00\x00\x00\x00"
        b"\x88\x77\x66\x55\x44\x33\x22\x11"
        b"\x09\x00\x00\x00\x00\x00\x00\x00"
        b"\x11\x11\x11\x11\x11\x11\x11\x11"
        b"\x11\x11\x11\x11\x11\x11\x11\x11"
    )

    unpacked_header = SMBHeader.unpack(actual)[0]
    assert isinstance(unpacked_header, SMB2Header)
    assert unpacked_header.async_id == 0x1122334455667788
    assert unpacked_header.tree_id == 0


def test_smb2_header_unpack() -> None:
    data = (
        b"\xFE\x53\x4D\x42"
        b"\x40\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x01\x00"
        b"\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x01\x00\x00\x00\x00\x00\x00\x00"
        b"\x0F\x00\x00\x00"
        b"\x01\x00\x00\x00"
        b"\x0A\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    actual_header, actual_size = SMBHeader.unpack(data)

    assert actual_size == 64
    assert isinstance(actual_header, SMB2Header)
    assert actual_header.protocol_id == b"\xFESMB"
    assert actual_header.credit_charge == 0
    assert actual_header.channel_sequence == 0
    assert actual_header.status == 0
    assert actual_header.command == Command.SESSION_SETUP
    assert actual_header.credit_charge == 0
    assert actual_header.flags == HeaderFlags.NONE
    assert actual_header.next_command == 0
    assert actual_header.message_id == 1
    assert actual_header.async_id == 0
    assert actual_header.tree_id == 1
    assert actual_header.session_id == 10
    assert actual_header.signature == b"\x00" * 16
