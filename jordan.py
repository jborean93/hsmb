import asyncio
import struct
import typing

import spnego
import xca

import hsmb


class XPressHuffman(hsmb.CompressionProvider):
    def __init__(self) -> None:
        self.lz77_huffman = xca.XpressHuffman()

    @property
    def compression_ids(self) -> typing.List[hsmb.messages.CompressionAlgorithm]:
        return [hsmb.messages.CompressionAlgorithm.LZ77_HUFFMAN]

    @classmethod
    def can_chain(cls) -> bool:
        return True

    def compress(
        self,
        algorithms: typing.List[hsmb.messages.CompressionAlgorithm],
        data: bytearray,
        hints: typing.List[slice],
        supports_chaining: bool,
    ) -> bytearray:
        if hsmb.messages.CompressionAlgorithm.LZ77_HUFFMAN not in algorithms:
            raise Exception("Requested algorithm is not supported")

        # Windows only compresses the data if it's more than 4KiB
        if len(data) < 4096:
            return data

        if not hints:
            hints.append(slice(0, len(data)))

        view = memoryview(data)
        if supports_chaining:
            pre_consumed = 0
            consumed = 0
            transformed: typing.List[bytearray] = []

            headers: typing.List[hsmb.messages.CompressionChainedPayloadHeader] = []
            for hint in hints:
                start = hint.start or 0
                stop = hint.stop

                if start > consumed:
                    headers.append(
                        hsmb.messages.CompressionChainedPayloadHeader(
                            compression_algorithm=hsmb.messages.CompressionAlgorithm.NONE,
                            flags=hsmb.messages.CompressionFlags.NONE
                            if len(headers)
                            else hsmb.messages.CompressionFlags.CHAINED,
                            data=view[consumed:start],
                        )
                    )
                    pre_consumed = consumed
                    consumed += start - consumed

                plain_length = stop - start
                if plain_length < 4096:
                    comp_data = b""  # Causes the below to just append non-compressed data
                else:
                    comp_data = self.lz77_huffman.compress(view[start:stop])

                if comp_data and len(comp_data) < plain_length:
                    # Compression was successful and smaller, add the compressed data
                    transformed.append(bytearray(plain_length.to_bytes(4, byteorder="little") + comp_data))

                    headers.append(
                        hsmb.messages.CompressionChainedPayloadHeader(
                            compression_algorithm=hsmb.messages.CompressionAlgorithm.LZ77_HUFFMAN,
                            flags=hsmb.messages.CompressionFlags.NONE
                            if len(headers)
                            else hsmb.messages.CompressionFlags.CHAINED,
                            data=memoryview(transformed[-1]),
                        )
                    )

                elif headers and headers[-1].compression_algorithm == hsmb.messages.CompressionAlgorithm.NONE:
                    # The last header was a NONE payload, need to adjust the view to include this next offset
                    old = headers.pop(-1)
                    headers.append(
                        hsmb.messages.CompressionChainedPayloadHeader(
                            compression_algorithm=hsmb.messages.CompressionAlgorithm.NONE,
                            flags=old.flags,
                            data=view[pre_consumed:stop],
                        )
                    )

                else:
                    # No last header or it was not a NONE payload, add the new NONE payload with the plaintex data
                    headers.append(
                        hsmb.messages.CompressionChainedPayloadHeader(
                            compression_algorithm=hsmb.messages.CompressionAlgorithm.NONE,
                            flags=hsmb.messages.CompressionFlags.NONE
                            if len(headers)
                            else hsmb.messages.CompressionFlags.CHAINED,
                            data=view[start:stop],
                        )
                    )

                pre_consumed = start
                consumed = stop

            if consumed < len(view):
                headers.append(
                    hsmb.messages.CompressionChainedPayloadHeader(
                        compression_algorithm=hsmb.messages.CompressionAlgorithm.NONE,
                        flags=hsmb.messages.CompressionFlags.NONE,
                        data=view[consumed:],
                    )
                )

            comp_data = hsmb.messages.CompressionTransformChained(
                original_compressed_segment_size=consumed,
                compression_payload_header=headers,
            ).pack()

            if len(comp_data) > consumed:
                return data
            else:
                return comp_data

        else:
            # Can only do 1 block of compression at the end, select the last hint to compress to the end
            start = hints[-1].start or 0

            final_block = bytearray(view[:start])
            to_compress = view[start:]
            to_compress_length = len(to_compress)
            if to_compress_length < 4096:
                return data

            comp_data = self.lz77_huffman.compress(to_compress)
            if len(comp_data) > to_compress_length:
                return data

            final_block += comp_data
            return hsmb.messages.CompressionTransformUnchained(
                original_compressed_segment_size=to_compress_length,
                compression_algorithm=hsmb.messages.CompressionAlgorithm.LZ77_HUFFMAN,
                flags=hsmb.messages.CompressionFlags.NONE,
                offset=start,
                data=memoryview(final_block),
            ).pack()

    def decompress(
        self,
        header: hsmb.messages.CompressionTransform,
    ) -> bytearray:
        buffer = bytearray()
        if isinstance(header, hsmb.messages.CompressionTransformChained):
            for chain in header.compression_payload_header:
                buffer += self._decompress_data(chain.data, chain.compression_algorithm)

            if len(buffer) != header.original_compressed_segment_size:
                raise Exception("Decompressed data does not match expected size")

        elif isinstance(header, hsmb.messages.CompressionTransformUnchained):
            buffer += header.data[: header.offset]
            buffer += self._decompress_data(
                header.data[header.offset :],
                header.compression_algorithm,
                length=header.original_compressed_segment_size,
            )

        return buffer

    def _decompress_data(
        self,
        data: memoryview,
        algorithm: hsmb.messages.CompressionAlgorithm,
        length: int = 0,
    ) -> bytes:
        if algorithm == hsmb.messages.CompressionAlgorithm.NONE:
            return bytes(data)

        elif algorithm == hsmb.messages.CompressionAlgorithm.LZ77_HUFFMAN:
            if not length:
                length = struct.unpack("<I", data[0:4])[0]
                data = data[4:]
            return self.lz77_huffman.decompress(data, length)

        else:
            raise Exception(f"Received compressed data with unsupported algorithm {algorithm!s}")


class TcpConnection:
    def __init__(
        self,
        host: str,
        port: int = 445,
    ) -> None:
        self.host = host
        self.port = port
        self._reader: typing.Optional[asyncio.StreamReader] = None
        self._writer: typing.Optional[asyncio.StreamWriter] = None

    async def __aenter__(self) -> "TcpConnection":
        self._reader, self._writer = await asyncio.open_connection(self.host, self.port)

        return self

    async def __aexit__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        if self._writer:
            self._writer.close()
            await self._writer.wait_closed()
            self._reader = self._writer = None

    async def send(self, data: bytes) -> None:
        if not self._writer:
            raise Exception("Connection is not open")

        self._writer.write(len(data).to_bytes(4, byteorder="big"))
        self._writer.write(data)
        await self._writer.drain()

    async def recv(self) -> bytes:
        if not self._reader:
            raise Exception("Connection is not open")

        raw_len = await self._reader.read(4)
        if not raw_len:
            raise Exception("No data received")

        data_len = struct.unpack(">I", raw_len)[0]
        buffer = bytearray()
        while len(buffer) != data_len:
            buffer += await self._reader.read(data_len)

        return bytes(buffer)


async def main() -> None:
    server = "127.0.0.1"
    username = "smbuser"
    password = "smbpass"

    # server = "server2022.domain.test"
    # username = "vagrant-domain@DOMAIN.TEST"
    # password = "VagrantPass1"

    # server = "192.168.80.10"
    # username = "vagrant"
    # password = "vagrant"

    async with TcpConnection(server, 445) as tcp:
        conn = hsmb.SMBClient(
            hsmb.ClientConfig(
                registered_compressor=XPressHuffman(),
                encrypt_all_requests=False,
                compress_all_requests=False,
            )
        )
        conn.negotiate(server)

        await tcp.send(conn.data_to_send())
        conn.receive_data(await tcp.recv())
        event = conn.next_event()
        assert isinstance(event, hsmb.ProtocolNegotiated)
        connection = event.connection

        auth = spnego.client(username, password)
        token = auth.step(event.token)
        session_id = 0

        while not auth.complete:
            conn.session_setup(token, session_id=session_id)

            await tcp.send(conn.data_to_send())
            conn.receive_data(await tcp.recv())
            event = conn.next_event()

            in_token = getattr(event, "token", None)
            if in_token:
                token = auth.step(in_token)

            session_id = getattr(event, "session_id", session_id)
            if isinstance(event, hsmb.SessionAuthenticated):
                conn.set_session_key(auth.session_key, event)
                break

        try:
            conn.request_credits(64)
            conn.tree_connect(session_id, f"\\\\{server}\\share")
            while not isinstance(event, hsmb.TreeConnected):
                await tcp.send(conn.data_to_send())
                conn.receive_data(await tcp.recv())
                event = conn.next_event()

            tree_id = event.tree.tree_connect_id
            try:

                if connection.compression_ids:
                    conn.create(
                        tree_id,
                        session_id,
                        "large.vhdx",
                        hsmb.messages.CreateDisposition.OPEN,
                        desired_access=0x02000000,
                        share_access=hsmb.messages.ShareAccess.READ,
                    )
                    await tcp.send(conn.data_to_send())
                    while True:
                        event = conn.next_event()
                        if not event:
                            conn.receive_data(await tcp.recv())
                        elif isinstance(event, hsmb.FileOpened):
                            break

                    file_open = event.open
                    try:
                        conn.read(file_open, 0, 65536, compress=True)
                        await tcp.send(conn.data_to_send())
                        conn.receive_data(await tcp.recv())
                        event = conn.next_event()

                    finally:
                        conn.close(file_open.file_id, session_id, query_attrib=True)
                        await tcp.send(conn.data_to_send())
                        conn.receive_data(await tcp.recv())
                        event = conn.next_event()

                    conn.create(
                        tree_id,
                        session_id,
                        "large.txt",
                        hsmb.messages.CreateDisposition.SUPERSEDE,
                        desired_access=0x02000000,
                        share_access=hsmb.messages.ShareAccess.WRITE | hsmb.messages.ShareAccess.READ,
                    )
                    await tcp.send(conn.data_to_send())
                    while True:
                        event = conn.next_event()
                        if not event:
                            conn.receive_data(await tcp.recv())
                        elif isinstance(event, hsmb.FileOpened):
                            break

                    file_open = event.open
                    try:
                        conn.write(file_open, 0, b"a" * 65536, compress_write=True)
                        await tcp.send(conn.data_to_send())
                        conn.receive_data(await tcp.recv())
                        event = conn.next_event()

                    finally:
                        conn.close(file_open.file_id, session_id, query_attrib=True)
                        await tcp.send(conn.data_to_send())
                        conn.receive_data(await tcp.recv())
                        event = conn.next_event()

                conn.create(
                    tree_id,
                    session_id,
                    "file.txt",
                    hsmb.messages.CreateDisposition.SUPERSEDE,
                    desired_access=0x02000000,
                )
                await tcp.send(conn.data_to_send())
                conn.receive_data(await tcp.recv())
                event = conn.next_event()
                assert isinstance(event, hsmb.FileOpened)

                file_open = event.open
                try:
                    conn.write(file_open, 0, b"Hello World")
                    await tcp.send(conn.data_to_send())
                    conn.receive_data(await tcp.recv())
                    event = conn.next_event()
                    assert isinstance(event, hsmb.MessageReceived)

                    conn.read(file_open, 0, 11)
                    await tcp.send(conn.data_to_send())
                    conn.receive_data(await tcp.recv())
                    event = conn.next_event()
                    assert isinstance(event, hsmb.MessageReceived)

                    conn.read(file_open, 11, 10)
                    await tcp.send(conn.data_to_send())
                    conn.receive_data(await tcp.recv())
                    event = conn.next_event()
                    assert isinstance(event, hsmb.ErrorReceived)

                finally:
                    conn.close(file_open.file_id, session_id, query_attrib=True)
                    await tcp.send(conn.data_to_send())
                    conn.receive_data(await tcp.recv())
                    event = conn.next_event()

                conn.echo(session_id=session_id)
                await tcp.send(conn.data_to_send())
                conn.receive_data(await tcp.recv())
                event = conn.next_event()
                assert isinstance(event, hsmb.MessageReceived)

                with hsmb.ClientTransaction(conn, related=True) as transaction:
                    conn.create(
                        tree_id,
                        session_id,
                        "file.txt",
                        hsmb.messages.CreateDisposition.SUPERSEDE,
                        desired_access=0x02000000,
                        transaction=transaction,
                    )
                    conn.write(None, 0, b"Hello World", transaction=transaction)
                    conn.read(None, 0, 11, transaction=transaction)
                    conn.read(None, 11, 10, transaction=transaction)

                await tcp.send(conn.data_to_send())
                conn.receive_data(await tcp.recv())
                while True:
                    event = conn.next_event()
                    if not event:
                        break

            finally:
                conn.tree_disconnect(session_id, tree_id)
                await tcp.send(conn.data_to_send())
                conn.receive_data(await tcp.recv())
                event = conn.next_event()

        finally:
            conn.logoff(session_id)
            await tcp.send(conn.data_to_send())
            conn.receive_data(await tcp.recv())
            event = conn.next_event()


if __name__ == "__main__":
    asyncio.run(main())
