from __future__  import annotations
from dataclasses import dataclass
from typing      import Any, Dict, ClassVar
from interface   import Message
from common      import PROTOCOL_VERSION, ProtocolError  # wherever you keep these

@dataclass(frozen=True)
class RegisterMessage(Message):
    TYPE: ClassVar[str] = "REGISTER"
    
    worker_id : str
    threads   : int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type"      : "REGISTER",
            "v"         : PROTOCOL_VERSION, 
            "worker_id" : self.worker_id, 
            "threads"   : int(self.threads)
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "RegisterMessage":
        if d.get("type") != "REGISTER" or d.get("v") != PROTOCOL_VERSION:
            raise ProtocolError("Expected REGISTER message.")
        return RegisterMessage(worker_id=str(d["worker_id"]), threads=int(d["threads"]))
