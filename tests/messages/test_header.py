from __future__ import annotations

import pytest

from hsmb import MalformedPacket
from hsmb.messages import (
    Command,
    CompressionAlgorithm,
    CompressionChainedPayloadHeader,
    CompressionFlags,
    CompressionPatternPayloadV1,
    CompressionTransform,
    CompressionTransformChained,
    CompressionTransformUnchained,
    HeaderFlags,
    SMB2Header,
    SMBHeader,
    TransformFlags,
    TransformHeader,
)


def test_unpack_header_too_small() -> None:
    with pytest.raises(
        MalformedPacket, match="Not enough data to unpack SMB header payload"
    ):
        SMBHeader.unpack(b"123")


def test_unpack_header_invalid_protocol() -> None:
    with pytest.raises(
        MalformedPacket, match="Unknown SMB Header protocol id 11223344"
    ):
        SMBHeader.unpack(b"\x11\x22\x33\x44")


@pytest.mark.skip()  # FIXME
def test_smb1_header_pack() -> None:
    raise NotImplementedError()


@pytest.mark.skip()  # FIXME
def test_smb1_header_unpack() -> None:
    raise NotImplementedError()


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


def test_smb2_header_unpack_too_small() -> None:
    with pytest.raises(MalformedPacket, match="Not enough data to unpack SMB2Header"):
        SMBHeader.unpack(b"\xFESMB123")


def test_transform_header_pack() -> None:
    transform = TransformHeader(
        signature=b"\x11" * 16,
        nonce=b"\x22" * 16,
        original_message_size=10,
        flags=TransformFlags.ENCRYPTED,
        session_id=0x1122334455667788,
    )

    actual = transform.pack()
    assert isinstance(actual, bytearray)
    assert actual == (
        b"\xFD\x53\x4D\x42"
        b"\x11\x11\x11\x11\x11\x11\x11\x11"
        b"\x11\x11\x11\x11\x11\x11\x11\x11"
        b"\x22\x22\x22\x22\x22\x22\x22\x22"
        b"\x22\x22\x22\x22\x22\x22\x22\x22"
        b"\x0A\x00\x00\x00"
        b"\x00\x00"
        b"\x01\x00"
        b"\x88\x77\x66\x55\x44\x33\x22\x11"
    )


def test_transform_header_unpack() -> None:
    data = (
        b"\xFD\x53\x4D\x42"
        b"\x11\x11\x11\x11\x11\x11\x11\x11"
        b"\x11\x11\x11\x11\x11\x11\x11\x11"
        b"\x22\x22\x22\x22\x22\x22\x22\x22"
        b"\x22\x22\x22\x22\x22\x22\x22\x22"
        b"\x0A\x00\x00\x00"
        b"\x00\x00"
        b"\x01\x00"
        b"\x88\x77\x66\x55\x44\x33\x22\x11"
    )

    actual_header, actual_size = SMBHeader.unpack(data)

    assert actual_size == 52
    assert isinstance(actual_header, TransformHeader)
    assert actual_header.protocol_id == b"\xFDSMB"
    assert actual_header.signature == b"\x11" * 16
    assert actual_header.nonce == b"\x22" * 16
    assert actual_header.original_message_size == 10
    assert actual_header.flags == TransformFlags.ENCRYPTED
    assert actual_header.session_id == 0x1122334455667788


def test_transform_header_unpack_too_small() -> None:
    with pytest.raises(
        MalformedPacket, match="Not enough data to unpack TransformHeader"
    ):
        SMBHeader.unpack(b"\xFDSMB123")


def test_comp_transform_unpack_too_small() -> None:
    with pytest.raises(
        MalformedPacket, match="Not enough data to unpack CompressionTransform"
    ):
        SMBHeader.unpack(b"\xFCSMB123")


def test_comp_unchained_pack() -> None:
    comp = CompressionTransformUnchained(
        original_compressed_segment_size=10,
        compression_algorithm=CompressionAlgorithm.LZ77,
        flags=CompressionFlags.NONE,
        offset=10,
        data=memoryview(b"\x11\x22\x33\x44"),
    )

    actual = comp.pack()
    assert isinstance(actual, bytearray)
    assert (
        actual == b"\xFC\x53\x4D\x42"
        b"\x0A\x00\x00\x00"
        b"\x02\x00"
        b"\x00\x00"
        b"\x0A\x00\x00\x00"
        b"\x11\x22\x33\x44"
    )


def test_comp_unchained_unpack() -> None:
    data = b"\xFC\x53\x4D\x42\x0A\x00\x00\x00\x02\x00\x00\x00\x0A\x00\x00\x00\x11\x22\x33\x44"
    actual_header, actual_size = SMBHeader.unpack(data)

    assert actual_size == 20
    assert isinstance(actual_header, CompressionTransformUnchained)
    assert actual_header.protocol_id == b"\xFCSMB"
    assert actual_header.original_compressed_segment_size == 10
    assert actual_header.compression_algorithm == CompressionAlgorithm.LZ77
    assert actual_header.flags == CompressionFlags.NONE
    assert actual_header.offset == 10
    assert actual_header.data == b"\x11\x22\x33\x44"


def test_comp_transform_unchained_unpack_too_small() -> None:
    with pytest.raises(
        MalformedPacket, match="Not enough data to unpack CompressionTransformUnchained"
    ):
        SMBHeader.unpack(b"\xFCSMB\x0A\x00\x00\x00\x02\x00\x00\x00")


def test_comp_chained_pack() -> None:
    comp = CompressionTransformChained(
        original_compressed_segment_size=10,
        compression_payload_header=[
            CompressionChainedPayloadHeader(
                compression_algorithm=CompressionAlgorithm.NONE,
                flags=CompressionFlags.CHAINED,
                data=memoryview(b"\x11\x22\x33\x44"),
            ),
            CompressionChainedPayloadHeader(
                compression_algorithm=CompressionAlgorithm.LZ77_HUFFMAN,
                flags=CompressionFlags.NONE,
                data=memoryview(b"\x55\x66\x77\x88"),
            ),
        ],
    )

    actual = comp.pack()
    assert isinstance(actual, bytearray)
    assert actual == (
        b"\xFC\x53\x4D\x42"
        b"\x0A\x00\x00\x00"
        b"\x00\x00"
        b"\x01\x00"
        b"\x04\x00\x00\x00"
        b"\x11\x22\x33\x44"
        b"\x03\x00"
        b"\x00\x00"
        b"\x04\x00\x00\x00"
        b"\x55\x66\x77\x88"
    )


def test_comp_transform_chained_unpack() -> None:
    data = (
        b"\xFC\x53\x4D\x42"
        b"\x0A\x00\x00\x00"
        b"\x00\x00"
        b"\x01\x00"
        b"\x04\x00\x00\x00"
        b"\x11\x22\x33\x44"
        b"\x03\x00"
        b"\x00\x00"
        b"\x04\x00\x00\x00"
        b"\x55\x66\x77\x88"
    )

    actual_header, actual_size = SMBHeader.unpack(data)

    assert actual_size == 32
    assert isinstance(actual_header, CompressionTransformChained)
    assert actual_header.protocol_id == b"\xFCSMB"
    assert actual_header.original_compressed_segment_size == 10
    assert isinstance(actual_header.compression_payload_header, list)
    assert len(actual_header.compression_payload_header) == 2
    assert (
        actual_header.compression_payload_header[0].compression_algorithm
        == CompressionAlgorithm.NONE
    )
    assert actual_header.compression_payload_header[0].flags == CompressionFlags.CHAINED
    assert actual_header.compression_payload_header[0].data == memoryview(
        b"\x11\x22\x33\x44"
    )
    assert (
        actual_header.compression_payload_header[1].compression_algorithm
        == CompressionAlgorithm.LZ77_HUFFMAN
    )
    assert actual_header.compression_payload_header[1].flags == CompressionFlags.NONE
    assert actual_header.compression_payload_header[1].data == memoryview(
        b"\x55\x66\x77\x88"
    )


def test_comp_transform_chained_unpack_too_small() -> None:
    with pytest.raises(
        MalformedPacket, match="Not enough data to unpack CompressionTransformChained"
    ):
        SMBHeader.unpack(b"\xFCSMB\x0A\x00\x00\x00\x02\x00\x01\x00")


def test_comp_chained_header_pack() -> None:
    comp = CompressionChainedPayloadHeader(
        compression_algorithm=CompressionAlgorithm.NONE,
        flags=CompressionFlags.CHAINED,
        data=memoryview(b"\x11\x22\x33\x44"),
    )

    actual = comp.pack()
    assert isinstance(actual, bytearray)
    assert actual == b"\x00\x00\x01\x00\x04\x00\x00\x00\x11\x22\x33\x44"


def test_comp_chained_header_unpack() -> None:
    data = b"\x00\x00\x01\x00\x04\x00\x00\x00\x11\x22\x33\x44"

    actual_header, actual_size = CompressionChainedPayloadHeader.unpack(data)

    assert actual_size == 12
    assert isinstance(actual_header, CompressionChainedPayloadHeader)
    assert actual_header.compression_algorithm == CompressionAlgorithm.NONE
    assert actual_header.flags == CompressionFlags.CHAINED
    assert actual_header.data == memoryview(b"\x11\x22\x33\x44")


def test_comp_chained_header_unpack_too_small() -> None:
    with pytest.raises(
        MalformedPacket,
        match="Not enough data to unpack CompressionChainedPayloadHeader",
    ):
        CompressionChainedPayloadHeader.unpack(b"\x11\x22\x33\x44\x55\x66\x77")


def test_comp_chained_header_unpack_out_of_bounds() -> None:
    with pytest.raises(
        MalformedPacket,
        match="Data for CompressionChainedPayloadHeader is out of bound",
    ):
        SMBHeader.unpack(
            b"\xFCSMB\x0A\x00\x00\x00\x02\x00\x01\x00\x04\x00\x00\x00\x11\x22\x33"
        )


def test_comp_pattern_v1_pack() -> None:
    comp = CompressionPatternPayloadV1(pattern=1, repetitions=10)

    actual = comp.pack()
    assert isinstance(actual, bytearray)
    assert actual == b"\x01\x00\x00\x00\x0A\x00\x00\x00"


def test_comp_pattern_v1_unpack() -> None:
    data = b"\x01\x00\x00\x00\x0A\x00\x00\x00"

    actual_header, actual_size = CompressionPatternPayloadV1.unpack(data)

    assert actual_size == 8
    assert isinstance(actual_header, CompressionPatternPayloadV1)
    assert actual_header.pattern == 1
    assert actual_header.repetitions == 10


def test_comp_pattern_v1_unpack_too_small() -> None:
    with pytest.raises(
        MalformedPacket, match="Not enough data to unpack CompressionPatternPayloadV1"
    ):
        CompressionPatternPayloadV1.unpack(b"\x11\x22\x33\x44\x55\x66\x77")
