from __future__  import annotations
from dataclasses import dataclass
from typing      import Any, Dict, Optional
from interface   import Message
from common      import PROTOCOL_VERSION, ProtocolError

@dataclass(frozen=True)
class ChunkDoneMessage(Message):
    chunk_id     : int
    tested       : int
    compute_time : float
    found        : bool = False
    password     : Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type"         : "CHUNK_DONE",
            "v"            : PROTOCOL_VERSION,
            "chunk_id"     : int(self.chunk_id),
            "tested"       : int(self.tested),
            "compute_time" : float(self.compute_time),
            "found"        : bool(self.found),
            "password"     : self.password,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "ChunkDoneMessage":
        if d.get("type") != "CHUNK_DONE" or d.get("v") != PROTOCOL_VERSION:
            raise ProtocolError("Expected CHUNK_DONE message.")
        return ChunkDoneMessage(
            chunk_id     = int(d["chunk_id"]),
            tested       = int(d.get("tested", 0)),
            compute_time = float(d.get("compute_time", 0.0)),
            found        = bool(d.get("found", False)),
            password     = d.get("password", None),
        )