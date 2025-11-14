
from pydantic import BaseModel
from typing import Optional, Literal
import json
from .utils import b64decode

# Base class with serialization helpers
class BaseMessage(BaseModel):
    type: str

    def to_json(self) -> str:
        # Convert to JSON
        return json.dumps(self.model_dump(), separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> "BaseMessage":
        return cls.model_validate(json.loads(raw))


# Control messages
class HelloMessage(BaseMessage):
    type: Literal["hello"] = "hello"
    client_cert: str
    nonce: str

class ServerHello(BaseMessage):
    type: Literal["server hello"] = "server hello"
    server_cert: str
    nonce: str

class RegisterMessage(BaseMessage):
    type: Literal["register"] = "register"
    email: str
    username: str
    pwd: str
    salt: str

class LoginMessage(BaseMessage):
    type: Literal["login"] = "login"
    email: str
    pwd: str
    nonce: Optional[str] = None


# DH messages
class DHClient(BaseMessage):
    type: Literal["dh_client"] = "dh_client"
    p: str   # because these may be large integers
    g: str
    A: str

class DHServer(BaseMessage):
    type: Literal["dh_server"] = "dh_server"
    B: str


# Data plane message
class Msg(BaseMessage):
    type: Literal["msg"] = "msg"
    seqno: int
    ts: int
    ct: str
    sig: str

    def ct_bytes(self) -> bytes:
        return b64decode(self.ct)

    def sig_bytes(self) -> bytes:
        return b64decode(self.sig)


# Receipt
class Receipt(BaseMessage):
    type: Literal["receipt"] = "receipt"
    peer: str
    first_seq: int
    last_seq: int
    transcript_sha256: str
    sig: str


# Error
class ErrorMessage(BaseMessage):
    type: Literal["error"] = "error"
    reason: str


_MSG_TYPE_MAP = {
    "hello": HelloMessage,
    "server hello": ServerHello,
    "register": RegisterMessage,
    "login": LoginMessage,
    "dh_client": DHClient,
    "dh_server": DHServer,
    "msg": Msg,
    "receipt": Receipt,
    "error": ErrorMessage,
}


def parse_message(raw_json: str) -> BaseMessage:
    payload = json.loads(raw_json)
    msg_type = payload.get("type")

    cls = _MSG_TYPE_MAP.get(msg_type)
    if cls is None:
        # Fallback: unknown message type
        return BaseMessage.model_validate(payload)

    return cls.model_validate(payload)
