from __future__  import annotations
from dataclasses import dataclass
from typing      import Any, Dict
from interface   import Message
from common      import PROTOCOL_VERSION, ProtocolError 

@dataclass(frozen=True)
class WorkerDoneMessage(Message):
    worker_id        : str
    runtime_sec      : float
    chunks_completed : int
    total_tested     : int
    found            : bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type"             : "WORKER_DONE",
            "v"                : PROTOCOL_VERSION,
            "worker_id"        : self.worker_id,
            "runtime_sec"      : float(self.runtime_sec),
            "chunks_completed" : int(self.chunks_completed),
            "total_tested"     : int(self.total_tested),
            "found"            : bool(self.found),
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "WorkerDoneMessage":
        if d.get("type") != "WORKER_DONE" or d.get("v") != PROTOCOL_VERSION:
            raise ProtocolError("Expected WORKER_DONE message.")
        return WorkerDoneMessage(
            worker_id        = str(d.get("worker_id", "")),
            runtime_sec      = float(d.get("runtime_sec", 0.0)),
            chunks_completed = int(d.get("chunks_completed", 0)),
            total_tested     = int(d.get("total_tested", 0)),
            found            = bool(d.get("found", False)),
        )