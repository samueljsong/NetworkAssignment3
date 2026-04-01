from __future__  import annotations
from dataclasses import dataclass
from typing      import Any, Dict
from interface   import Message
from common      import PROTOCOL_VERSION, ProtocolError 

@dataclass(frozen=True)
class ChunkAssignMessage(Message):
    chunk_id : int
    start    : int          # global index start (inclusive)
    count    : int          # number of candidates in this chunk

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type"     : "CHUNK_ASSIGN", 
            "v"        : PROTOCOL_VERSION, 
            "chunk_id" : int(self.chunk_id), 
            "start"    : int(self.start), 
            "count"    : int(self.count)}

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "ChunkAssignMessage":
        if d.get("type") != "CHUNK_ASSIGN" or d.get("v") != PROTOCOL_VERSION:
            raise ProtocolError("Expected CHUNK_ASSIGN message.")
        return ChunkAssignMessage(chunk_id=int(d["chunk_id"]), start=int(d["start"]), count=int(d["count"]))
