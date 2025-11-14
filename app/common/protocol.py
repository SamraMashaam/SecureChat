# app/common/protocol.py
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
    type: Literal["dh client"] = "dh client"
    g: int
    p: int
    A: int

class DHServer(BaseMessage):
    type: Literal["dh server"] = "dh server"
    B: int


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
    "dh client": DHClient,
    "dh server": DHServer,
    "msg": Msg,
    "receipt": Receipt,
    "error": ErrorMessage,
}

def parse_message(raw_json: str) -> BaseMessage:
    # Parse JSON string and return an instance of the appropriate message class
    payload = json.loads(raw_json)
    cls = _MSG_TYPE_MAP.get(payload.get("type"))
    if cls is None:
        return BaseMessage.model_validate(payload)
    return cls.model_validate(payload)
