# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import hsmb


def test_negotiate() -> None:
    c = hsmb.SMBClient(hsmb.ClientConfig())
    s = hsmb.SMBServer(hsmb.ServerConfig())

    c.negotiate("server")
    s.receive_data(c.data_to_send())
    a = ""
