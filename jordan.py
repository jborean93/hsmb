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
        conn = hsmb.SMBClientConnection(hsmb.SMBClientConfig(), server)
        conn.open()

        await tcp.send(conn.data_to_send())
        conn.receive_data(await tcp.recv())
        conn.next_event()

        auth = spnego.client(username, password)
        token = auth.step(conn.gss_negotiate_token)

        with hsmb.SMBClientSession(conn) as session:
            while not auth.complete:
                event = conn.next_event()

                if not event:
                    session.open(token)

                    await tcp.send(conn.data_to_send())
                    conn.receive_data(await tcp.recv())
                    continue

                if isinstance(event, hsmb.SecurityTokenReceived):
                    if event.token:
                        token = auth.step(event.token)

                    if event.require_session_key:
                        session.set_session_key(auth.session_key)

            conn.tree_connect(session, f"\\\\{server}\\share")
            await tcp.send(conn.data_to_send())
            conn.receive_data(await tcp.recv())
            event = conn.next_event()
            conn.tree_disconnect(list(session.tree_connect_table.values())[0])
            a = ""

        await tcp.send(conn.data_to_send())
        conn.receive_data(await tcp.recv())
        conn.next_event()


if __name__ == "__main__":
    asyncio.run(main())
