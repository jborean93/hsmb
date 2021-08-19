import asyncio
import os
import struct
import uuid

import hsmb


def tcp_write(writer: asyncio.StreamWriter, data: bytearray) -> None:
    writer.write(len(data).to_bytes(4, byteorder="big"))
    writer.write(data)


async def main() -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", 445)
    conn = hsmb.SMBConnection(hsmb.SMBConfiguration(hsmb.SMBRole.CLIENT), uuid.uuid4())
    salt = os.urandom(32)

    header1 = hsmb.SMB1Header(
        command=0x72,
        status=0,
        flags=hsmb.SMB1HeaderFlags.NONE,
        pid=0,
        tid=0,
        uid=0,
        mid=0,
    )
    nego1 = hsmb.SMB1NegotiateRequest(dialects=["NT LM 0.12", "SMB 2.002", "SMB 2.???"])
    multi_nego = bytearray(header1.pack() + nego1.pack())
    tcp_write(writer, multi_nego)
    data_len = await reader.read(4)
    resp = await reader.read(struct.unpack(">I", data_len)[0])
    resp_header, resp_header_length = hsmb.unpack_header(resp)
    if isinstance(resp_header, hsmb.SMB1Header):
        nego_resp = hsmb.SMB1NegotiateResponse.unpack(resp, resp_header_length)
    else:
        nego_resp = hsmb.NegotiateResponse.unpack(resp, resp_header_length)

    nego = hsmb.NegotiateRequest(
        dialects=[
            hsmb.Dialect.SMB311,
        ],
        security_mode=hsmb.SecurityModes.SIGNING_REQUIRED,
        capabilities=hsmb.Capabilities.CAP_ENCRYPTION | hsmb.Capabilities.LARGE_MTU,
        client_guid=conn.identifier,
        negotiate_contexts=[
            hsmb.PreauthIntegrityCapabilities(
                hash_algorithms=[hsmb.HashAlgorithm.SHA512],
                salt=salt,
            ),
            hsmb.EncryptionCapabilities(
                ciphers=[hsmb.Cipher.AES128_CCM, hsmb.Cipher.AES128_GCM],
            ),
        ],
    )
    conn.send(nego)

    tcp_write(writer, conn._data_to_send)
    data_len = await reader.read(4)
    resp = await reader.read(struct.unpack(">I", data_len)[0])
    resp_header, resp_header_length = hsmb.unpack_header(resp)
    nego_resp = hsmb.NegotiateResponse.unpack(resp, resp_header_length)
    a = hsmb.NegotiateRequest.unpack(nego.pack())
    nego_resp.pack()

    a = ""


if __name__ == "__main__":
    asyncio.run(main())
