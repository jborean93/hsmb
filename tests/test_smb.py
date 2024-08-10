from __future__ import annotations

import hsmb


def test_negotiate() -> None:
    c = hsmb.SMBClient(hsmb.ClientConfig())
    s = hsmb.SMBServer(hsmb.ServerConfig())

    c.negotiate("server")
    s.receive_data(c.data_to_send())
    a = s.next_event()
    c.receive_data(s.data_to_send())
    b = c.next_event()
