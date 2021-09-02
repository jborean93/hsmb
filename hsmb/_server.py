# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""
class SMBServerConnection(SMBConnection[SMBServerConfig]):

    def __init__(
        self,
        config: SMBServerConfig,
        max_transact_size: int = 65536,
        max_read_size: int = 65536,
        max_write_size: int = 65536,
        security_buffer: typing.Optional[bytes] = None,
    ) -> None:
        super().__init__(config)
        self.max_transact_size = max_transact_size
        self.max_read_size = max_read_size
        self.max_write_size = max_write_size
        self.security_buffer = security_buffer

    def negotiate(self, message: typing.Union[SMB1NegotiateRequest, NegotiateRequest]) -> None:
        if isinstance(message, SMB1NegotiateRequest):
            if self._negotiate_smb1(message):
                return

        else:
            if self.dialect and self.dialect != Dialect.SMB2_WILDCARD:
                raise ValueError("Already negotiated")

            self.server_capabilities = message.capabilities
            self.server_identifier = message.client_guid

            if len(message.dialects) == 0:
                raise ValueError("Return STATUS_INVALID_PARAMETER")

            # FIXME: STATUS_NOT_SUPPORTED if no dialect match
            self.dialect = sorted(message.dialects, reverse=True)[0]

        nego_resp = NegotiateResponse(
            security_mode=self.client_security_mode,
            dialect_revision=self.dialect,
            server_guid=self.client_identifier,
            capabilities=self.client_capabilities,
            max_transact_size=self.max_transact_size,
            max_read_size=self.max_read_size,
            max_write_size=self.max_write_size,
            security_buffer=self.security_buffer,
            negotiate_contexts=[],
        )
        self.send(nego_resp, credits=1)

    def _negotiate_smb1(self, message: SMB1NegotiateRequest) -> bool:
        if "SMB 2.002" in message.dialects:
            self.dialect = Dialect.SMB202
        elif "SMB 2.???" in message.dialects:
            self.dialect = Dialect.SMB2_WILDCARD

        if self.dialect:
            self.client_security_mode = SecurityModes.SIGNING_ENABLED
            if self.config.require_message_signing:
                self.client_security_mode = SecurityModes.SIGNING_REQUIRED

            self.client_identifier = self.config.identifier
            self.client_capabilities = Capabilities.NONE
            # FIXME: Add DFS capability based on config
            # FIXME: Set LEASING, LARGE_MTU if wildcard
            # FIXME: Max sizes should be 65536 if 2.0.2
            return False

        else:
            resp = SMB1NegotiateResponse(selected_index=-1)
            self.send_smb1(resp)
            return True
"""
