import asyncio
import os
import struct
import uuid

import spnego

import hsmb


async def tcp_write(writer: asyncio.StreamWriter, data: bytes) -> None:
    writer.write(len(data).to_bytes(4, byteorder="big"))
    writer.write(data)
    await writer.drain()


async def tcp_read(reader: asyncio.StreamReader) -> bytes:
    raw_len = await reader.read(4)
    data_len = struct.unpack(">I", raw_len)[0]
    return await reader.read(data_len)


async def main() -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", 445)
    conn = hsmb.SMBClientConnection(hsmb.SMBClientConfig(), "127.0.0.1")
    conn.open()

    while True:
        data = conn.data_to_send()
        if not data:
            break

        await tcp_write(writer, data)
        conn.receive_data(await tcp_read(reader))
        event = conn.next_event()

    auth = spnego.client("smbuser", "smbpassword")
    token = auth.step(conn.gss_negotiate_token)
    session = hsmb.SMBClientSession(conn)

    while True:
        session.open(token)
        data = conn.data_to_send()
        if not data:
            break

        await tcp_write(writer, data)
        conn.receive_data(await tcp_read(reader))
        event = conn.next_event()

        if event.header.status == 0:
            break

        elif event.header.status != 0xC0000016:
            raise Exception(f"Received unknown status {event.header.status}")

        else:
            session.session_id = event.header.session_id
            token = event.message.security_buffer

    a = ""


if __name__ == "__main__":
    asyncio.run(main())
