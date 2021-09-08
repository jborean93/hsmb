import asyncio
import struct
import typing

import spnego
import xca

import hsmb


class XPressHuffman(hsmb.CompressionAlgorithmBase):
    def __init__(self) -> None:
        self.lz77_huffman = xca.XpressHuffman()

    @classmethod
    def compression_ids(cls) -> typing.List[hsmb.CompressionAlgorithm]:
        return [hsmb.CompressionAlgorithm.LZ77_HUFFMAN]

    @classmethod
    def can_chain(cls) -> bool:
        return True

    def compress(
        self,
        algorithms: typing.List[hsmb.CompressionAlgorithm],
        data: bytearray,
        hints: typing.List[slice],
        supports_chaining: bool,
    ) -> bytearray:
        if hsmb.CompressionAlgorithm.LZ77_HUFFMAN not in algorithms:
            raise Exception("Requested algorithm is not supported")

        # Windows only compresses the data if it's more than 4KiB
        if len(data) < 4096:
            return data

        if not hints:
            hints.append(slice(0, len(data)))

        buffer = bytearray()
        if supports_chaining:
            consumed = 0
            for hint_slice in hints:
                start = hint_slice.start or 0
                stop = hint_slice.stop

                if start > consumed:
                    # TODO: Add NONE block
                    buffer += data[consumed : consumed + start]
                    consumed += consumed + start

            if len(data) > consumed:
                # TODO: Add NONE block
                buffer += data[consumed:]

                a = ""

            if len(buffer) > data:
                buffer = data

        else:
            # Can only do 1 block of compression at the end, select the last hint
            hint_slice = hints[-1]
            a = ""

        raise NotImplementedError()
        return buffer

    def decompress(
        self,
        header: hsmb.CompressionTransform,
    ) -> bytearray:
        buffer = bytearray()
        if isinstance(header, hsmb.CompressionTransformChained):
            for chain in header.compression_payload_header:
                buffer += self._decompress_data(chain.data, chain.compression_algorithm)

            if len(buffer) != header.original_compressed_segment_size:
                raise Exception("Decompressed data does not match expected size")

        elif isinstance(header, hsmb.CompressionTransformUnchained):
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
        algorithm: hsmb.CompressionAlgorithm,
        length: int = 0,
    ) -> bytes:
        if algorithm == hsmb.CompressionAlgorithm.NONE:
            return bytes(data)

        elif algorithm == hsmb.CompressionAlgorithm.LZ77_HUFFMAN:
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
    # server = "127.0.0.1"
    # username = "smbuser"
    # password = "smbpass"

    server = "server2022.domain.test"
    username = "vagrant-domain@DOMAIN.TEST"
    password = "VagrantPass1"

    async with TcpConnection(server, 445) as tcp:
        conn = hsmb.SMBClient(hsmb.ClientConfig(registered_compressor=XPressHuffman, encrypt_all_requests=False))
        conn.negotiate(server)

        await tcp.send(conn.data_to_send())
        conn.receive_data(await tcp.recv())
        event = conn.next_event()
        assert isinstance(event, hsmb.ProtocolNegotiated)
        connection = conn.connection

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

                conn.create(
                    tree_id,
                    session_id,
                    "large.vhdx",
                    hsmb.CreateDisposition.OPEN,
                    desired_access=0x02000000,
                    share_access=hsmb.ShareAccess.READ,
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
                    hsmb.CreateDisposition.SUPERSEDE,
                    desired_access=0x02000000,
                    share_access=hsmb.ShareAccess.WRITE | hsmb.ShareAccess.READ,
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

                return

                conn.create(
                    tree_id,
                    session_id,
                    "file.txt",
                    hsmb.CreateDisposition.SUPERSEDE,
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
                        hsmb.CreateDisposition.SUPERSEDE,
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
