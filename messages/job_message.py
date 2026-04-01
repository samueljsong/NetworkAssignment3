from __future__  import annotations
from dataclasses import dataclass
from typing      import Any, Dict
from interface   import Message
from common      import PROTOCOL_VERSION, ProtocolError

@dataclass(frozen=True)
class JobMessage(Message):
    full_hash           : str
    length              : int
    charset             : str
    chunk_size          : int
    heartbeat_seconds   : float
    checkpoint_interval : int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type"                : "JOB",
            "v"                   : PROTOCOL_VERSION,
            "hash"                : self.full_hash,
            "length"              : int(self.length),
            "charset"             : self.charset,
            "chunk_size"          : int(self.chunk_size),
            "heartbeat_seconds"   : float(self.heartbeat_seconds),
            "checkpoint_interval" : int(self.checkpoint_interval),
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "JobMessage":
        if d.get("type") != "JOB" or d.get("v") != PROTOCOL_VERSION:
            raise ProtocolError("Expected JOB message.")
        return JobMessage(
            full_hash           = str(d["hash"]),
            length              = int(d["length"]),
            charset             = str(d["charset"]),
            chunk_size          = int(d["chunk_size"]),
            heartbeat_seconds   = float(d.get("heartbeat_seconds", 1.0)),
            checkpoint_interval = int(d.get("checkpoint_interval", 1000)),
        )