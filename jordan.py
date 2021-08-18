import asyncio
import uuid

import hsmb


async def main() -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", 445)
    conn = hsmb.SMBConnection(hsmb.SMBConfiguration(hsmb.SMBRole.CLIENT), uuid.uuid4())

    nego = hsmb.NegotiateRequest(
        dialects=[],
        security_mode=hsmb.SecurityModes.SIGNING_ENABLED,
        capabilities=hsmb.Capabilities.CAP_ENCRYPTION,
        client_guid=conn.identifier,
        negotiate_contexts=[],
    )
    conn.send(nego)

    a = ""


if __name__ == "__main__":
    asyncio.run(main())
