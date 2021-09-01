import asyncio
import struct
import typing

import spnego

import hsmb


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
        return await self._reader.read(data_len)


async def main() -> None:
    server = "127.0.0.1"
    username = "smbuser"
    password = "smbpass"

    # server = "server2022.domain.test"
    # username = "vagrant-domain@DOMAIN.TEST"
    # password = "VagrantPass1"

    async with TcpConnection(server, 445) as tcp:
        conn = hsmb.SMBClient(hsmb.ClientConfig())
        conn.negotiate(server)

        await tcp.send(conn.data_to_send())
        conn.receive_data(await tcp.recv())
        protocol_negotiated = conn.next_event()
        assert isinstance(protocol_negotiated, hsmb.ProtocolNegotiated)

        auth = spnego.client(username, password)
        token = auth.step(protocol_negotiated.token)

        conn.session_setup(token)
        await tcp.send(conn.data_to_send())
        conn.receive_data(await tcp.recv())
        event = conn.next_event()
        assert isinstance(event, hsmb.SessionProcessingRequired)

        token = auth.step(event.token)

        conn.session_setup(token, session_id=event.session_id)
        await tcp.send(conn.data_to_send())
        conn.receive_data(await tcp.recv())
        event = conn.next_event()
        assert isinstance(event, hsmb.SessionAuthenticated)

        conn.set_session_key(auth.session_key, event)

        session_id = event.session_id
        try:
            conn.tree_connect(session_id, f"\\\\{server}\\share")
            await tcp.send(conn.data_to_send())
            conn.receive_data(await tcp.recv())
            event = conn.next_event()
            assert isinstance(event, hsmb.TreeConnected)

            tree_id = event.tree.tree_connect_id
            try:
                a = ""

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
