import uuid

from hsmb import Dialect, NegotiateRequest, PreauthIntegrityCapabilities

pre_auth = PreauthIntegrityCapabilities(hash_algorithms=[], salt=b"")
req = NegotiateRequest(
    dialects=[Dialect.smb311],
    security_mode=1,
    capabilities=2,
    client_guid=uuid.uuid4(),
    negotiate_contexts=[],
)


a = ""
